import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.agent_status import mark_stale_hosts_offline, trap_status_view
from app.audit import write_audit
from app.database import get_db
from app.event_view import can_view_sensitive_event_data, redact_event_data
from app.jobs import create_trap_job, enqueue_profile_application
from app.models import EnrollmentToken, Event, Host, HoneypotInstance, HostStatus, TrapProfile, TrapStatus, UserRole, utcnow
from app.provisioning import ensure_profile_ports_available
from app.routes.auth import client_ip
from app.schemas import (
    EnrollmentCreate,
    EnrollmentCreated,
    EventRead,
    HostInput,
    HostRead,
    ProfileInput,
    ProfileRead,
    SessionInfo,
    JobRead,
    TrapJobCreate,
    TrapInstanceCreate,
    TrapRead,
    UserRead,
)
from app.security import AuthContext, get_auth_context, require_roles, token_hash, verify_csrf

router = APIRouter(prefix="/api/v1", tags=["api"])
all_roles = (UserRole.ADMIN, UserRole.OPERATOR, UserRole.OBSERVER)
writers = (UserRole.ADMIN, UserRole.OPERATOR)


def profile_state(profile: TrapProfile) -> dict:
    return ProfileRead.model_validate(profile).model_dump(mode="json")


def trap_read(instance: HoneypotInstance) -> TrapRead:
    view = trap_status_view(instance)
    return TrapRead(
        id=instance.id,
        name=instance.name,
        host_id=instance.host_id,
        profile_id=instance.profile_id,
        status=view.status,
        reported_status=view.reported_status,
        host_status=view.host_status,
        status_stale=view.status_stale,
        last_seen_at=instance.last_seen_at,
        created_at=instance.created_at,
    )


@router.get("/auth/me", response_model=SessionInfo)
def me(context: AuthContext = Depends(get_auth_context)):
    return SessionInfo(user=UserRead.model_validate(context.user), csrf_token=context.session.csrf_token)


@router.get("/profiles", response_model=list[ProfileRead])
def list_profiles(
    context: AuthContext = Depends(require_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    return list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))


@router.post("/profiles", response_model=ProfileRead, status_code=status.HTTP_201_CREATED)
def create_profile(
    payload: ProfileInput,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, x_csrf_token)
    profile = TrapProfile(**payload.model_dump(mode="json"))
    db.add(profile)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Профиль с таким именем уже существует") from exc
    write_audit(
        db,
        actor=context.user,
        action="profile.create",
        entity_type="trap_profile",
        entity_id=profile.id,
        after=profile_state(profile),
        source_ip=client_ip(request),
    )
    enqueue_profile_application(
        db,
        profile=profile,
        actor=context.user,
        source_ip=client_ip(request),
    )
    db.commit()
    db.refresh(profile)
    return profile


@router.put("/profiles/{profile_id}", response_model=ProfileRead)
def update_profile(
    profile_id: uuid.UUID,
    payload: ProfileInput,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, x_csrf_token)
    profile = db.get(TrapProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    before = profile_state(profile)
    for key, value in payload.model_dump(mode="json").items():
        setattr(profile, key, value)
    profile.config_version += 1
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Профиль с таким именем уже существует") from exc
    write_audit(
        db,
        actor=context.user,
        action="profile.update",
        entity_type="trap_profile",
        entity_id=profile.id,
        before=before,
        after=profile_state(profile),
        source_ip=client_ip(request),
    )
    enqueue_profile_application(
        db,
        profile=profile,
        actor=context.user,
        source_ip=client_ip(request),
    )
    db.commit()
    db.refresh(profile)
    return profile


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(
    profile_id: uuid.UUID,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, x_csrf_token)
    profile = db.get(TrapProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    before = profile_state(profile)
    db.delete(profile)
    write_audit(
        db,
        actor=context.user,
        action="profile.delete",
        entity_type="trap_profile",
        entity_id=profile.id,
        before=before,
        source_ip=client_ip(request),
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Профиль используется экземпляром ловушки") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/hosts", response_model=list[HostRead])
def list_hosts(
    context: AuthContext = Depends(require_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    return list(db.scalars(select(Host).order_by(Host.name)))


@router.get("/traps", response_model=list[TrapRead])
def list_traps(
    context: AuthContext = Depends(require_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    instances = list(
        db.scalars(
            select(HoneypotInstance)
            .options(selectinload(HoneypotInstance.host))
            .order_by(HoneypotInstance.name)
        )
    )
    return [trap_read(instance) for instance in instances]


@router.post("/traps", response_model=TrapRead, status_code=status.HTTP_201_CREATED)
def create_trap(
    payload: TrapInstanceCreate,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(*writers)),
    db: Session = Depends(get_db),
):
    """Attach another trap instance to an already provisioned host.

    The host keeps its single agent identity; configuration and event ownership
    continue to be scoped by that host in the agent API.
    """
    verify_csrf(context, x_csrf_token)
    host = db.get(Host, payload.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    profile = db.get(TrapProfile, payload.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    try:
        ensure_profile_ports_available(db, host.id, profile)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    instance = HoneypotInstance(
        name=payload.name,
        host=host,
        profile=profile,
        status=TrapStatus.PENDING,
    )
    db.add(instance)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Trap instance name is already in use") from exc
    write_audit(
        db,
        actor=context.user,
        action="trap.create",
        entity_type="honeypot_instance",
        entity_id=instance.id,
        after={
            "name": instance.name,
            "host_id": str(instance.host_id),
            "profile_id": str(instance.profile_id),
        },
        source_ip=client_ip(request),
    )
    db.commit()
    db.refresh(instance)
    return trap_read(instance)


@router.post("/traps/{trap_id}/jobs", response_model=JobRead, status_code=status.HTTP_201_CREATED)
def create_job(
    trap_id: uuid.UUID,
    payload: TrapJobCreate,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, x_csrf_token)
    instance = db.get(HoneypotInstance, trap_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Trap not found")
    job = create_trap_job(
        db,
        instance=instance,
        command=payload.command,
        payload=payload.payload,
        actor=context.user,
        source_ip=client_ip(request),
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/enrollments", response_model=EnrollmentCreated, status_code=status.HTTP_201_CREATED)
def create_enrollment(
    payload: EnrollmentCreate,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    context: AuthContext = Depends(require_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, x_csrf_token)
    validated_host = HostInput(
        name=payload.host_name,
        management_address=payload.management_address,
        description="",
    )
    profile = db.get(TrapProfile, payload.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    host = Host(
        name=validated_host.name,
        management_address=validated_host.management_address,
        description=validated_host.description,
        status=HostStatus.OFFLINE,
    )
    instance = HoneypotInstance(
        name=payload.instance_name,
        host=host,
        profile=profile,
        status=TrapStatus.PENDING,
    )
    raw_token = secrets.token_urlsafe(48)
    expires_at = utcnow() + timedelta(minutes=payload.ttl_minutes)
    enrollment = EnrollmentToken(
        host=host,
        token_hash=token_hash(raw_token),
        expires_at=expires_at,
        created_by_id=context.user.id,
    )
    db.add_all([host, instance, enrollment])
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Имя хоста или экземпляра уже используется") from exc
    write_audit(
        db,
        actor=context.user,
        action="agent.enrollment_created",
        entity_type="host",
        entity_id=host.id,
        after={"host_name": host.name, "instance_name": instance.name, "expires_at": expires_at},
        source_ip=client_ip(request),
    )
    db.commit()
    return EnrollmentCreated(
        host_id=host.id,
        instance_id=instance.id,
        enrollment_token=raw_token,
        expires_at=expires_at,
    )


@router.get("/events", response_model=list[EventRead])
def list_events(
    instance_id: uuid.UUID | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
    context: AuthContext = Depends(require_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    query = select(Event)
    if instance_id:
        query = query.where(Event.instance_id == instance_id)
    if from_time:
        query = query.where(Event.occurred_at >= from_time)
    if to_time:
        query = query.where(Event.occurred_at <= to_time)
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if event_type:
        query = query.where(Event.event_type == event_type)
    events = list(db.scalars(query.order_by(Event.occurred_at.desc()).limit(limit)))
    allow_sensitive = can_view_sensitive_event_data(context.user.role)
    return [
        EventRead.model_validate(event).model_copy(
            update={"data": redact_event_data(event.data, allow_sensitive=allow_sensitive)}
        )
        for event in events
    ]
