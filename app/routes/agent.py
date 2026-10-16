from __future__ import annotations

import uuid
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.agent_auth import AgentContext, get_agent_context, require_agent_gateway
from app.audit import write_audit
from app.database import get_db
from app.honeytokens import candidate_hashes, redact_known_honeytokens
from app.models import (
    AgentIdentity,
    Alert,
    EnrollmentToken,
    Event,
    Honeytoken,
    HoneypotInstance,
    HostStatus,
    Job,
    TrapStatus,
    utcnow,
)
from app.pki import sign_agent_csr
from app.realtime import event_manager
from app.schemas import (
    AgentConfigResponse,
    AgentEnrollmentRequest,
    AgentEnrollmentResponse,
    AgentHeartbeat,
    AgentStatusReport,
    AgentProfileConfig,
    EventBatch,
    EventBatchAck,
    EventRead,
    JobAck,
    JobRead,
    ProfileRead,
    RotateCertificateRequest,
    RotateCertificateResponse,
)
from app.security import token_hash

router = APIRouter(prefix="/agent/v1", tags=["agent"])


@router.post("/enroll", response_model=AgentEnrollmentResponse)
def enroll_agent(payload: AgentEnrollmentRequest, request: Request, db: Session = Depends(get_db)):
    require_agent_gateway(request)
    record = db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.token_hash == token_hash(payload.token))
        .with_for_update()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if record.used_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Enrollment token already used")
    if expires_at <= utcnow():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Enrollment token expired")
    if db.scalar(select(AgentIdentity).where(AgentIdentity.host_id == record.host_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Host already has an agent identity")

    identity_id = uuid.uuid4()
    try:
        certificate_pem, fingerprint, pin, certificate_expires_at = sign_agent_csr(
            payload.csr_pem, identity_id, record.host_id
        )
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Invalid certificate request") from exc
    from cryptography import x509

    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    identity = AgentIdentity(
        id=identity_id,
        host_id=record.host_id,
        certificate_serial=format(certificate.serial_number, "x"),
        certificate_fingerprint_sha256=fingerprint,
        public_key_pin_sha256=pin,
        expires_at=certificate_expires_at,
        last_seen_at=utcnow(),
    )
    record.used_at = utcnow()
    host = record.host
    host.agent_id = str(identity_id)
    host.status = HostStatus.ONLINE
    host.last_seen_at = utcnow()
    db.add(identity)
    db.flush()
    write_audit(
        db,
        actor=None,
        action="agent.registered",
        entity_type="agent_identity",
        entity_id=identity.id,
        after={"host_id": host.id, "certificate_expires_at": certificate_expires_at},
        source_ip=request.headers.get("x-real-ip"),
    )
    db.commit()
    return AgentEnrollmentResponse(
        identity_id=identity.id,
        host_id=host.id,
        certificate_pem=certificate_pem,
        certificate_expires_at=certificate_expires_at,
    )


def touch_agent(db: Session, context: AgentContext) -> None:
    now = utcnow()
    context.identity.last_seen_at = now
    context.host.last_seen_at = now
    context.host.status = HostStatus.ONLINE


@router.post("/heartbeat")
def heartbeat(
    payload: AgentHeartbeat,
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    touch_agent(db, context)
    db.commit()
    return {"status": "ok", "server_time": utcnow(), "host_id": context.host.id}


@router.post("/status")
def report_trap_status(
    payload: AgentStatusReport,
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    instances = {
        item.id: item
        for item in db.scalars(
            select(HoneypotInstance).where(HoneypotInstance.host_id == context.host.id)
        )
    }
    if any(item.instance_id not in instances for item in payload.statuses):
        raise HTTPException(status_code=403, detail="Status references a foreign trap")
    now = utcnow()
    for item in payload.statuses:
        instance = instances[item.instance_id]
        instance.status = TrapStatus(item.state)
        instance.last_seen_at = now
    touch_agent(db, context)
    db.commit()
    return {"status": "ok", "updated": len(payload.statuses)}


@router.get("/config", response_model=AgentConfigResponse)
def get_configuration(
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    instances = list(
        db.scalars(
            select(HoneypotInstance)
            .where(HoneypotInstance.host_id == context.host.id)
            .options(selectinload(HoneypotInstance.profile))
            .order_by(HoneypotInstance.name)
        )
    )
    touch_agent(db, context)
    db.commit()
    return AgentConfigResponse(
        host_id=context.host.id,
        configurations=[
            AgentProfileConfig(
                instance_id=item.id,
                instance_name=item.name,
                profile=ProfileRead.model_validate(item.profile),
            )
            for item in instances
        ],
    )


@router.post("/events", response_model=EventBatchAck)
async def collect_events(
    payload: EventBatch,
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    allowed_instances = set(
        db.scalars(select(HoneypotInstance.id).where(HoneypotInstance.host_id == context.host.id))
    )
    if any(item.instance_id not in allowed_instances for item in payload.events):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Event references a foreign trap")

    requested_ids = [str(item.external_id) for item in payload.events]
    duplicate_ids = set(db.scalars(select(Event.external_id).where(Event.external_id.in_(requested_ids))))
    new_items = [item for item in payload.events if str(item.external_id) not in duplicate_ids]
    possible_hashes: set[str] = set()
    for item in new_items:
        possible_hashes.update(candidate_hashes(item.data))
        reported_hashes = item.data.get("_honeytoken_hashes", [])
        if isinstance(reported_hashes, list):
            possible_hashes.update(
                value.lower()
                for value in reported_hashes
                if isinstance(value, str)
                and len(value) == 64
                and all(char in "0123456789abcdefABCDEF" for char in value)
            )
    honeytokens = list(
        db.scalars(
            select(Honeytoken)
            .where(Honeytoken.token_hash.in_(sorted(possible_hashes)))
            .order_by(Honeytoken.token_hash)
            .with_for_update()
        )
    ) if possible_hashes else []
    tokens_by_hash = {token.token_hash: token for token in honeytokens}
    existing_alert_keys = {
        (
            str(alert.details.get("honeytoken_id") or alert.details.get("honeytoken_scope")),
            alert.details.get("source_ip"),
        )
        for alert in db.scalars(select(Alert).where(Alert.state == "open"))
        if alert.details.get("kind") == "honeytoken_use"
    }
    accepted: list[uuid.UUID] = []
    created_events: list[Event] = []
    for item in new_items:
        external_id = str(item.external_id)
        high_honeytoken_use = (
            item.event_type.startswith("high.http")
            and item.data.get("_high_honeytoken_use") is True
        )
        event_data = {
            key: value
            for key, value in item.data.items()
            if key not in {"_honeytoken_hashes", "_high_honeytoken_use"}
        }
        reported_hashes = item.data.get("_honeytoken_hashes", [])
        if not isinstance(reported_hashes, list):
            reported_hashes = []
        matched_by_id = {
            str(token.id): token
            for digest in reported_hashes
            for token in [tokens_by_hash.get(str(digest).lower())]
            if token is not None
        }
        if tokens_by_hash:
            event_data, inline_matches = redact_known_honeytokens(event_data, tokens_by_hash)
            matched_by_id.update({str(token.id): token for token in inline_matches})
        matched_tokens = list(matched_by_id.values())
        event = Event(
            external_id=external_id,
            instance_id=item.instance_id,
            agent_identity_id=context.identity.id,
            event_type=item.event_type,
            source_ip=item.source_ip,
            occurred_at=item.occurred_at,
            data=event_data,
            is_test=item.is_test,
        )
        db.add(event)
        db.flush()
        for honeytoken in matched_tokens:
            if not item.event_type.startswith("medium.http"):
                continue
            alert_key = (str(honeytoken.id), item.source_ip)
            if not honeytoken.is_active or alert_key in existing_alert_keys:
                continue
            severity = honeytoken.metadata_json.get("alert_severity", "high")
            db.add(
                Alert(
                    event_id=event.id,
                    severity=severity,
                    title=f"Обнаружено использование honeytoken «{honeytoken.name}»",
                    state="open",
                    details={
                        "kind": "honeytoken_use",
                        "honeytoken_id": str(honeytoken.id),
                        "honeytoken_name": honeytoken.name,
                        "token_type": honeytoken.token_type,
                        "source_ip": item.source_ip,
                        "event_type": item.event_type,
                        "reason": "Известный honeytoken обнаружен в телеметрии Medium HTTP.",
                    },
                )
            )
            existing_alert_keys.add(alert_key)
        if high_honeytoken_use:
            honeytoken_scope = f"high:{item.instance_id}"
            alert_key = (honeytoken_scope, item.source_ip)
            if alert_key not in existing_alert_keys:
                db.add(
                    Alert(
                        event_id=event.id,
                        severity="critical",
                        title="Использована приманка High HTTP",
                        state="open",
                        details={
                            "kind": "honeytoken_use",
                            "honeytoken_scope": honeytoken_scope,
                            "source_ip": item.source_ip,
                            "event_type": item.event_type,
                            "reason": "Внутренняя приманка из виртуального окружения High использована в HTTP-сценарии.",
                        },
                    )
                )
                existing_alert_keys.add(alert_key)
        created_events.append(event)
        accepted.append(item.external_id)
    touch_agent(db, context)
    db.commit()
    for event in created_events:
        db.refresh(event)
    for event in created_events:
        await event_manager.broadcast(jsonable_encoder(EventRead.model_validate(event)))
    return EventBatchAck(
        accepted_ids=accepted,
        duplicate_ids=[uuid.UUID(value) for value in duplicate_ids],
    )


@router.get("/jobs", response_model=list[JobRead])
def get_jobs(
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    jobs = list(
        db.scalars(
            select(Job)
            .where(Job.host_id == context.host.id, Job.state.in_(["pending", "delivered"]))
            .order_by(Job.created_at)
            .limit(50)
        )
    )
    now = utcnow()
    for job in jobs:
        job.state = "delivered"
        job.delivered_at = now
        job.attempt_count += 1
    touch_agent(db, context)
    db.commit()
    return jobs


@router.post("/jobs/{job_id}/ack")
def acknowledge_job(
    job_id: uuid.UUID,
    payload: JobAck,
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    job = db.get(Job, job_id)
    if not job or job.host_id != context.host.id:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.state in ("succeeded", "failed"):
        return {"status": job.state, "idempotent": True}
    allowed_commands = ("apply_config", "start_trap", "stop_trap", "collect_status")
    if payload.state == "succeeded" and job.command not in allowed_commands:
        raise HTTPException(status_code=409, detail="Unsupported job cannot be marked successful")
    job.state = payload.state
    job.result = payload.result
    job.acknowledged_at = utcnow()
    if job.instance_id and job.command in ("apply_config", "start_trap", "stop_trap"):
        instance = db.get(HoneypotInstance, job.instance_id)
        if instance:
            reported_state = payload.result.get("state")
            if payload.state == "failed":
                instance.status = TrapStatus.ERROR
            elif payload.state == "succeeded" and reported_state in ("online", "offline"):
                instance.status = TrapStatus(reported_state)
            instance.last_seen_at = utcnow()
    write_audit(
        db,
        actor=None,
        action="trap.job_acknowledged",
        entity_type="job",
        entity_id=job.id,
        after={"command": job.command, "state": job.state},
        source_ip=None,
    )
    touch_agent(db, context)
    db.commit()
    return {"status": job.state, "idempotent": False}


@router.post("/certificate/rotate", response_model=RotateCertificateResponse)
def rotate_certificate(
    payload: RotateCertificateRequest,
    context: AgentContext = Depends(get_agent_context),
    db: Session = Depends(get_db),
):
    try:
        certificate_pem, fingerprint, pin, expires_at = sign_agent_csr(
            payload.csr_pem, context.identity.id, context.host.id
        )
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Invalid certificate request") from exc
    from cryptography import x509

    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    context.identity.certificate_serial = format(certificate.serial_number, "x")
    context.identity.certificate_fingerprint_sha256 = fingerprint
    context.identity.public_key_pin_sha256 = pin
    context.identity.issued_at = utcnow()
    context.identity.expires_at = expires_at
    write_audit(
        db,
        actor=None,
        action="agent.certificate_rotated",
        entity_type="agent_identity",
        entity_id=context.identity.id,
        after={"host_id": context.host.id, "certificate_expires_at": expires_at},
        source_ip=None,
    )
    db.commit()
    return RotateCertificateResponse(certificate_pem=certificate_pem, certificate_expires_at=expires_at)
