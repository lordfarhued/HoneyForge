import csv
import json
import secrets
import uuid
from datetime import timedelta
from io import StringIO
from math import ceil
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import ValidationError
from sqlalchemy import Text, and_, case, cast, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.agent_status import mark_stale_hosts_offline, trap_status_view
from app.audit import write_audit
from app.database import get_db
from app.event_view import (
    ADMIN_PATH_MARKERS,
    SourceRiskAccumulator,
    can_view_sensitive_event_data,
    correlate_events,
    event_summary,
    redact_event_data,
    redact_export_event_data,
)
from app.honeytokens import generate_honeytoken
from app.jobs import ALLOWED_TRAP_COMMANDS, create_trap_job, enqueue_profile_application
from app.models import Alert, AuditEntry, EnrollmentToken, Event, Honeytoken, Host, HoneypotInstance, HostStatus, TrapProfile, TrapStatus, UserRole, utcnow
from app.provisioning import ensure_profile_ports_available
from app.routes.api import profile_state
from app.routes.auth import client_ip
from app.schemas import HostInput, ProfileInput, TrapInstanceCreate
from app.security import AuthContext, get_ui_auth_context, require_ui_roles, token_hash, verify_csrf
from app.time_format import format_moscow_time, parse_moscow_time

router = APIRouter(tags=["interface"])
all_roles = (UserRole.ADMIN, UserRole.OPERATOR, UserRole.OBSERVER)
writers = (UserRole.ADMIN, UserRole.OPERATOR)


def base_context(context: AuthContext, **values):
    return {"user": context.user, "csrf_token": context.session.csrf_token, **values}


ALERT_SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATES = ("open", "acknowledged", "closed")
ANALYTICS_SOURCE_LIMIT = 12
EVENT_EXPORT_LIMIT = 5_000
ALERT_EXPORT_LIMIT = 10_000


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    context: AuthContext = Depends(get_ui_auth_context),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    counts = {
        "profiles": db.scalar(select(func.count()).select_from(TrapProfile)) or 0,
        "hosts": db.scalar(select(func.count()).select_from(Host)) or 0,
        "traps": db.scalar(select(func.count()).select_from(HoneypotInstance)) or 0,
        "events": db.scalar(select(func.count()).select_from(Event)) or 0,
    }
    recent = list(db.scalars(select(AuditEntry).order_by(AuditEntry.created_at.desc()).limit(8)))
    recent_events = list(db.scalars(select(Event).order_by(Event.created_at.desc()).limit(20)))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context=base_context(context, counts=counts, recent=recent, recent_events=recent_events),
    )


@router.get("/analytics", response_class=HTMLResponse)
def analytics_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    has_source = and_(Event.source_ip.is_not(None), Event.source_ip != "")
    normalized_type = func.lower(Event.event_type)
    total_events, unique_sources, http_events, ssh_events = db.execute(
        select(
            func.count(Event.id),
            func.count(func.distinct(case((has_source, Event.source_ip), else_=None))),
            func.coalesce(func.sum(case((normalized_type.contains("http"), 1), else_=0)), 0),
            func.coalesce(func.sum(case((normalized_type.contains("ssh"), 1), else_=0)), 0),
        )
    ).one()
    total_events = int(total_events or 0)
    unique_sources = int(unique_sources or 0)
    http_events = int(http_events or 0)
    ssh_events = int(ssh_events or 0)
    other_events = max(0, total_events - http_events - ssh_events)
    active_alerts = int(
        db.scalar(select(func.count(Alert.id)).where(Alert.state == "open")) or 0
    )

    source_rows = db.execute(
        select(Event.source_ip, func.count(Event.id), func.max(Event.occurred_at))
        .where(has_source)
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc(), Event.source_ip)
        .limit(ANALYTICS_SOURCE_LIMIT)
    ).all()
    source_ips = [row[0] for row in source_rows]
    accumulators = {source_ip: SourceRiskAccumulator() for source_ip in source_ips}

    if source_ips:
        serialized_data = func.lower(cast(Event.data, Text))
        candidate_filter = or_(
            normalized_type.like("%\\_auth", escape="\\"),
            normalized_type.like("%ssh_command"),
            and_(
                normalized_type.contains("http"),
                or_(*(serialized_data.contains(marker) for marker in ADMIN_PATH_MARKERS)),
            ),
        )
        risk_events = db.scalars(
            select(Event)
            .where(Event.source_ip.in_(source_ips), candidate_filter)
            .execution_options(yield_per=250)
        )
        for event in risk_events:
            accumulators[event.source_ip].add_event(event)

        honeytoken_alerts = db.execute(
            select(Event.source_ip, Alert.event_id)
            .join(Event, Event.id == Alert.event_id)
            .where(
                Event.source_ip.in_(source_ips),
                Alert.details["kind"].as_string() == "honeytoken_use",
            )
        )
        for source_ip, event_id in honeytoken_alerts:
            accumulators[source_ip].add_honeytoken_event(event_id)

    sources = []
    for source_ip, event_count, last_activity in source_rows:
        assessment = accumulators[source_ip].assessment()
        sources.append(
            {
                "source_ip": source_ip,
                "event_count": int(event_count),
                "last_activity": last_activity,
                "events_url": f"/events?{urlencode({'source_ip': source_ip})}",
                **assessment,
            }
        )

    protocol_total = http_events + ssh_events + other_events
    protocols = [
        {
            "code": "http",
            "label": "HTTP",
            "count": http_events,
            "percent": round(http_events * 100 / protocol_total, 1) if protocol_total else 0,
        },
        {
            "code": "ssh",
            "label": "SSH",
            "count": ssh_events,
            "percent": round(ssh_events * 100 / protocol_total, 1) if protocol_total else 0,
        },
        {
            "code": "other",
            "label": "Прочие",
            "count": other_events,
            "percent": round(other_events * 100 / protocol_total, 1) if protocol_total else 0,
        },
    ]
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="analytics.html",
        context=base_context(
            context,
            total_events=total_events,
            unique_sources=unique_sources,
            active_alerts=active_alerts,
            protocols=protocols,
            sources=sources,
            source_limit=ANALYTICS_SOURCE_LIMIT,
        ),
    )


@router.get("/infrastructure", response_class=HTMLResponse)
def infrastructure_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    hosts = list(
        db.scalars(
            select(Host)
            .options(
                selectinload(Host.identity),
                selectinload(Host.instances).selectinload(HoneypotInstance.profile),
            )
            .order_by(Host.name)
        )
    )
    event_counts = dict(
        db.execute(select(Event.instance_id, func.count(Event.id)).group_by(Event.instance_id)).all()
    )
    status_labels = {
        "online": "Онлайн",
        "offline": "Офлайн",
        "degraded": "Нестабильно",
        "pending": "Ожидает",
        "error": "Ошибка",
        "unknown": "Неизвестно",
        "unregistered": "Не зарегистрирован",
        "unavailable": "Identity недоступна",
    }

    agents = []
    for host in hosts:
        identity = host.identity
        identity_active = bool(identity and identity.status == "active")
        center_connected = identity_active and host.status == HostStatus.ONLINE
        if identity is None:
            status_value = "unregistered"
        elif not identity_active:
            status_value = "unavailable"
        else:
            status_value = host.status.value

        traps = []
        for trap in sorted(host.instances, key=lambda item: item.name):
            state = trap_status_view(trap)
            traps.append(
                {
                    "id": trap.id,
                    "name": trap.name,
                    "level": trap.profile.interaction_level.value,
                    "status": state.status,
                    "status_label": status_labels[state.status],
                    "reported_status": state.reported_status.value,
                    "event_count": int(event_counts.get(trap.id, 0)),
                    "last_activity": trap.last_seen_at,
                }
            )

        agents.append(
            {
                "id": host.id,
                "name": host.name,
                "kind": "Агент" if identity is not None else "Хост без identity",
                "status": status_value,
                "status_label": status_labels[status_value],
                "center_connected": center_connected,
                "registered": identity is not None,
                "event_count": sum(item["event_count"] for item in traps),
                "last_activity": host.last_seen_at or (identity.last_seen_at if identity else None),
                "traps": traps,
            }
        )

    connected_agents = [agent for agent in agents if agent["center_connected"]]
    disconnected_agents = [agent for agent in agents if not agent["center_connected"]]
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="infrastructure.html",
        context=base_context(
            context,
            connected_agents=connected_agents,
            disconnected_agents=disconnected_agents,
            host_count=len(agents),
            registered_agent_count=sum(agent["registered"] for agent in agents),
            active_connection_count=len(connected_agents),
            trap_count=sum(len(agent["traps"]) for agent in agents),
            event_count=sum(event_counts.values()),
        ),
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_optional_uuid(value: str, parameter_name: str) -> uuid.UUID | None:
    value = value.strip()
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Некорректный параметр {parameter_name}") from exc


def _event_filter_conditions(
    *,
    event_type: str,
    instance_id: str,
    source_ip: str,
    from_time: str,
    to_time: str,
    q: str,
):
    parsed_instance_id = _parse_optional_uuid(instance_id, "instance_id")
    try:
        from_utc = parse_moscow_time(from_time)
        to_utc = parse_moscow_time(to_time)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Некорректный временной диапазон") from exc
    if from_utc and to_utc and from_utc > to_utc:
        raise HTTPException(status_code=422, detail="Начало диапазона должно быть раньше окончания")

    conditions = []
    if event_type:
        conditions.append(Event.event_type == event_type)
    if parsed_instance_id:
        conditions.append(Event.instance_id == parsed_instance_id)
    if source_ip:
        conditions.append(Event.source_ip == source_ip)
    if from_utc:
        conditions.append(Event.occurred_at >= from_utc)
    if to_utc:
        conditions.append(Event.occurred_at <= to_utc)
    if q.strip():
        conditions.append(cast(Event.data, Text).ilike(f"%{_escape_like(q.strip())}%", escape="\\"))
    return conditions, parsed_instance_id


@router.get("/events", response_class=HTMLResponse)
def events_page(
    request: Request,
    event_type: str = Query("", max_length=80),
    instance_id: str = Query("", max_length=64),
    source_ip: str = Query("", max_length=64),
    from_time: str = Query("", max_length=40),
    to_time: str = Query("", max_length=40),
    q: str = Query("", max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=10, le=100),
    event_id: str = Query("", max_length=64),
    context: AuthContext = Depends(require_ui_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    parsed_event_id = _parse_optional_uuid(event_id, "event_id")
    conditions, parsed_instance_id = _event_filter_conditions(
        event_type=event_type,
        instance_id=instance_id,
        source_ip=source_ip,
        from_time=from_time,
        to_time=to_time,
        q=q,
    )

    count_query = select(func.count()).select_from(Event).where(*conditions)
    total = db.scalar(count_query) or 0
    total_pages = max(1, ceil(total / page_size))
    current_page = min(page, total_pages)
    rows = db.execute(
        select(Event, HoneypotInstance.name)
        .join(HoneypotInstance, HoneypotInstance.id == Event.instance_id)
        .where(*conditions)
        .order_by(Event.occurred_at.desc(), Event.id.desc())
        .offset((current_page - 1) * page_size)
        .limit(page_size)
    ).all()
    events = [
        {"event": event, "trap_name": trap_name, "summary": event_summary(event.data or {})}
        for event, trap_name in rows
    ]
    allow_sensitive = can_view_sensitive_event_data(context.user.role)
    attack_timelines = correlate_events(
        [event for event, _ in rows],
        allow_sensitive=allow_sensitive,
    )


    selected_event = None
    selected_trap_name = None
    selected_json = None
    data_is_redacted = False
    if parsed_event_id:
        selected = db.execute(
            select(Event, HoneypotInstance.name)
            .join(HoneypotInstance, HoneypotInstance.id == Event.instance_id)
            .where(Event.id == parsed_event_id)
        ).one_or_none()
        if not selected:
            raise HTTPException(status_code=404, detail="Событие не найдено")
        selected_event, selected_trap_name = selected
        visible_data = redact_event_data(selected_event.data or {}, allow_sensitive=allow_sensitive)
        selected_json = json.dumps(visible_data, ensure_ascii=False, indent=2, sort_keys=True)
        data_is_redacted = not allow_sensitive

    traps = list(db.execute(select(HoneypotInstance.id, HoneypotInstance.name).order_by(HoneypotInstance.name)))
    event_types = list(db.scalars(select(Event.event_type).distinct().order_by(Event.event_type)))
    filters = {
        "event_type": event_type,
        "instance_id": str(parsed_instance_id) if parsed_instance_id else "",
        "source_ip": source_ip,
        "from_time": from_time,
        "to_time": to_time,
        "q": q,
        "page_size": page_size,
    }
    export_params = {
        key: value
        for key, value in filters.items()
        if key != "page_size" and value not in (None, "")
    }
    export_suffix = f"?{urlencode(export_params)}" if export_params else ""

    def events_url(*, target_page: int = current_page, selected_id: uuid.UUID | None = None) -> str:
        params = {key: value for key, value in filters.items() if value not in (None, "")}
        params["page"] = target_page
        if selected_id:
            params["event_id"] = str(selected_id)
        return f"/events?{urlencode(params)}"

    return request.app.state.templates.TemplateResponse(
        request=request,
        name="events.html",
        context=base_context(
            context,
            events=events,
            traps=traps,
            event_types=event_types,
            filters=filters,
            page=current_page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
            events_url=events_url,
            selected_event=selected_event,
            selected_trap_name=selected_trap_name,
            selected_json=selected_json,
            data_is_redacted=data_is_redacted,
            attack_timelines=attack_timelines,
            export_json_url=f"/events/export.json{export_suffix}",
            export_csv_url=f"/events/export.csv{export_suffix}",
        ),
    )


def _safe_export_alerts(db: Session, conditions: list) -> dict[uuid.UUID, list[dict]]:
    alert_total = db.scalar(
        select(func.count(Alert.id))
        .select_from(Alert)
        .join(Event, Event.id == Alert.event_id)
        .where(*conditions)
    ) or 0
    if alert_total > ALERT_EXPORT_LIMIT:
        raise HTTPException(
            status_code=413,
            detail=f"Экспорт содержит более {ALERT_EXPORT_LIMIT} связанных предупреждений; сузьте фильтры.",
        )
    alerts_by_event: dict[uuid.UUID, list[dict]] = {}
    rows = db.execute(
        select(
            Alert.id,
            Alert.event_id,
            Alert.severity,
            Alert.state,
            Alert.title,
            Alert.created_at,
        )
        .join(Event, Event.id == Alert.event_id)
        .where(*conditions)
        .order_by(Alert.event_id, Alert.created_at, Alert.id)
    )
    for alert_id, event_id, severity, state, title, created_at in rows:
        alerts_by_event.setdefault(event_id, []).append(
            {
                "id": str(alert_id),
                "event_id": str(event_id),
                "severity": severity,
                "state": state,
                "title": title,
                "created_at": created_at.isoformat(),
            }
        )
    return alerts_by_event


def _csv_safe_cell(value) -> str:
    text = "" if value is None else str(value)
    cleaned = "".join(" " if ord(char) < 32 or ord(char) == 127 else char for char in text)
    candidate = cleaned.lstrip()
    if candidate.startswith(("=", "+", "-", "@")):
        return f"'{cleaned}"
    return cleaned


@router.get("/events/export.{export_format}")
def export_events(
    export_format: str,
    event_type: str = Query("", max_length=80),
    instance_id: str = Query("", max_length=64),
    source_ip: str = Query("", max_length=64),
    from_time: str = Query("", max_length=40),
    to_time: str = Query("", max_length=40),
    q: str = Query("", max_length=200),
    context: AuthContext = Depends(require_ui_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    if export_format not in {"json", "csv"}:
        raise HTTPException(status_code=404, detail="Формат экспорта не поддерживается")
    conditions, parsed_instance_id = _event_filter_conditions(
        event_type=event_type,
        instance_id=instance_id,
        source_ip=source_ip,
        from_time=from_time,
        to_time=to_time,
        q=q,
    )
    event_total = int(db.scalar(select(func.count(Event.id)).where(*conditions)) or 0)
    if event_total > EVENT_EXPORT_LIMIT:
        raise HTTPException(
            status_code=413,
            detail=f"Экспорт ограничен {EVENT_EXPORT_LIMIT} событиями; сузьте временной диапазон или другие фильтры.",
        )
    alerts_by_event = _safe_export_alerts(db, conditions)
    allow_sensitive = can_view_sensitive_event_data(context.user.role)
    generated_at = utcnow()
    filters = {
        "event_type": event_type or None,
        "trap_id": str(parsed_instance_id) if parsed_instance_id else None,
        "source_ip": source_ip or None,
        "from_time": from_time or None,
        "to_time": to_time or None,
        "search_applied": bool(q.strip()),
    }

    def records():
        rows = db.execute(
            select(Event, HoneypotInstance.name)
            .join(HoneypotInstance, HoneypotInstance.id == Event.instance_id)
            .where(*conditions)
            .order_by(Event.occurred_at, Event.id)
            .execution_options(yield_per=250)
        )
        for event, trap_name in rows:
            yield {
                "id": str(event.id),
                "external_id": event.external_id,
                "occurred_at": event.occurred_at.isoformat(),
                "collected_at": event.created_at.isoformat(),
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "trap": {"id": str(event.instance_id), "name": trap_name},
                "is_test": event.is_test,
                "data": redact_export_event_data(event.data or {}, allow_sensitive=allow_sensitive),
                "alerts": alerts_by_event.get(event.id, []),
            }

    timestamp = generated_at.strftime("%Y%m%d-%H%M%SZ")
    filename = f"honeyforge-attack-report-{timestamp}.{export_format}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-HoneyForge-Export-Limit": str(EVENT_EXPORT_LIMIT),
    }
    if export_format == "json":
        def json_stream():
            metadata = {
                "schema": "honeyforge.attack-report.v1",
                "generated_at": generated_at.isoformat(),
                "filters": filters,
                "event_count": event_total,
            }
            yield json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))[:-1] + ',"events":['
            first = True
            for record in records():
                if not first:
                    yield ","
                yield json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                first = False
            yield "]}"

        return StreamingResponse(
            json_stream(), media_type="application/json; charset=utf-8", headers=headers
        )

    def csv_stream():
        output = StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        columns = (
            "id",
            "external_id",
            "occurred_at",
            "collected_at",
            "event_type",
            "source_ip",
            "trap_id",
            "trap_name",
            "is_test",
            "data_json",
            "alerts_json",
        )
        writer.writerow(columns)
        yield "\ufeff" + output.getvalue()
        output.seek(0)
        output.truncate(0)
        for record in records():
            writer.writerow(
                _csv_safe_cell(value)
                for value in (
                    record["id"],
                    record["external_id"],
                    record["occurred_at"],
                    record["collected_at"],
                    record["event_type"],
                    record["source_ip"],
                    record["trap"]["id"],
                    record["trap"]["name"],
                    str(record["is_test"]).lower(),
                    json.dumps(record["data"], ensure_ascii=False, separators=(",", ":")),
                    json.dumps(record["alerts"], ensure_ascii=False, separators=(",", ":")),
                )
            )
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    return StreamingResponse(csv_stream(), media_type="text/csv; charset=utf-8", headers=headers)


def render_honeytokens_page(
    request: Request,
    context: AuthContext,
    db: Session,
    *,
    revealed_token: str | None = None,
    error: str | None = None,
    status_code: int = 200,
):
    honeytokens = list(db.scalars(select(Honeytoken).order_by(Honeytoken.created_at.desc())))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="honeytokens.html",
        context=base_context(
            context,
            honeytokens=honeytokens,
            revealed_token=revealed_token,
            error=error,
            severities=ALERT_SEVERITIES,
        ),
        status_code=status_code,
    )


@router.get("/honeytokens", response_class=HTMLResponse)
def honeytokens_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    return render_honeytokens_page(request, context, db)


@router.post("/honeytokens", response_class=HTMLResponse)
def create_honeytoken_page(
    request: Request,
    name: str = Form(..., min_length=3, max_length=80),
    severity: str = Form("high"),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    if severity not in ALERT_SEVERITIES:
        raise HTTPException(status_code=422, detail="Некорректный уровень опасности")
    clean_name = name.strip()
    if len(clean_name) < 3:
        raise HTTPException(status_code=422, detail="Название должно содержать не менее трёх символов")
    raw_token = generate_honeytoken()
    honeytoken = Honeytoken(
        name=clean_name,
        token_type="medium_http",
        token_hash=token_hash(raw_token),
        metadata_json={"alert_severity": severity},
        is_active=True,
    )
    db.add(honeytoken)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return render_honeytokens_page(
            request,
            context,
            db,
            error="Honeytoken с таким именем уже существует.",
            status_code=409,
        )
    write_audit(
        db,
        actor=context.user,
        action="honeytoken.create",
        entity_type="honeytoken",
        entity_id=honeytoken.id,
        after={
            "name": honeytoken.name,
            "token_type": honeytoken.token_type,
            "alert_severity": severity,
            "is_active": True,
        },
        source_ip=client_ip(request),
    )
    db.commit()
    return render_honeytokens_page(request, context, db, revealed_token=raw_token)


@router.post("/honeytokens/{honeytoken_id}/state")
def set_honeytoken_state(
    honeytoken_id: uuid.UUID,
    request: Request,
    active: str = Form(...),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    if active not in ("true", "false"):
        raise HTTPException(status_code=422, detail="Некорректное состояние honeytoken")
    honeytoken = db.get(Honeytoken, honeytoken_id)
    if not honeytoken:
        raise HTTPException(status_code=404, detail="Honeytoken не найден")
    before = honeytoken.is_active
    honeytoken.is_active = active == "true"
    write_audit(
        db,
        actor=context.user,
        action="honeytoken.activate" if honeytoken.is_active else "honeytoken.deactivate",
        entity_type="honeytoken",
        entity_id=honeytoken.id,
        before={"name": honeytoken.name, "is_active": before},
        after={"name": honeytoken.name, "is_active": honeytoken.is_active},
        source_ip=client_ip(request),
    )
    db.commit()
    return RedirectResponse(url="/honeytokens", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    state: str = Query("", max_length=20),
    severity: str = Query("", max_length=20),
    context: AuthContext = Depends(require_ui_roles(*all_roles)),
    db: Session = Depends(get_db),
):
    if state and state not in ALERT_STATES:
        raise HTTPException(status_code=422, detail="Некорректное состояние предупреждения")
    if severity and severity not in ALERT_SEVERITIES:
        raise HTTPException(status_code=422, detail="Некорректный уровень опасности")
    conditions = []
    if state:
        conditions.append(Alert.state == state)
    if severity:
        conditions.append(Alert.severity == severity)
    alerts = list(
        db.execute(
            select(Alert, Event.external_id)
            .outerjoin(Event, Event.id == Alert.event_id)
            .where(*conditions)
            .order_by(Alert.created_at.desc())
        )
    )
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context=base_context(
            context,
            alerts=alerts,
            filters={"state": state, "severity": severity},
            states=ALERT_STATES,
            severities=ALERT_SEVERITIES,
        ),
    )


@router.get("/profiles", response_class=HTMLResponse)
def profiles_page(
    request: Request,
    context: AuthContext = Depends(get_ui_auth_context),
    db: Session = Depends(get_db),
):
    profiles = list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="profiles/list.html",
        context=base_context(context, profiles=profiles),
    )


def default_profile_form() -> dict:
    return {
        "name": "",
        "description": "",
        "interaction_level": "low",
        "services_json": '[\n  {"name": "ssh", "protocol": "tcp", "port": 22, "banner": "OpenSSH"}\n]',
        "bait_credentials_json": "[]",
        "logging_json": '{\n  "capture_connections": true,\n  "capture_credentials": true,\n  "capture_commands": true,\n  "capture_payloads": false\n}',
        "masking_json": '{\n  "endpoint_path": "/assets/telemetry",\n  "process_name": "system-metrics",\n  "install_path": "/opt/system-metrics",\n  "response_delay_ms": 0\n}',
    }


def profile_to_form(profile: TrapProfile) -> dict:
    return {
        "name": profile.name,
        "description": profile.description,
        "interaction_level": profile.interaction_level.value,
        "services_json": json.dumps(profile.services, ensure_ascii=False, indent=2),
        "bait_credentials_json": json.dumps(profile.bait_credentials, ensure_ascii=False, indent=2),
        "logging_json": json.dumps(profile.logging, ensure_ascii=False, indent=2),
        "masking_json": json.dumps(profile.masking, ensure_ascii=False, indent=2),
    }


def parse_profile_form(form: dict) -> ProfileInput:
    try:
        return ProfileInput(
            name=form["name"],
            description=form["description"],
            interaction_level=form["interaction_level"],
            services=json.loads(form["services_json"]),
            bait_credentials=json.loads(form["bait_credentials_json"]),
            logging=json.loads(form["logging_json"]),
            masking=json.loads(form["masking_json"]),
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"Некорректный JSON: {exc.msg}, строка {exc.lineno}") from exc


def render_profile_form(request: Request, context: AuthContext, form: dict, *, profile=None, error=None, code=200):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="profiles/form.html",
        context=base_context(context, form=form, profile=profile, error=error),
        status_code=code,
    )


@router.get("/profiles/new", response_class=HTMLResponse)
def new_profile_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*writers)),
):
    return render_profile_form(request, context, default_profile_form())


@router.post("/profiles/new", response_class=HTMLResponse)
def create_profile_page(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    interaction_level: str = Form(...),
    services_json: str = Form(...),
    bait_credentials_json: str = Form(...),
    logging_json: str = Form(...),
    masking_json: str = Form(...),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    form = locals().copy()
    try:
        payload = parse_profile_form(form)
    except (ValidationError, ValueError) as exc:
        return render_profile_form(request, context, form, error=str(exc), code=422)
    profile = TrapProfile(**payload.model_dump(mode="json"))
    db.add(profile)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return render_profile_form(request, context, form, error="Профиль с таким именем уже существует.", code=409)
    write_audit(
        db,
        actor=context.user,
        action="profile.create",
        entity_type="trap_profile",
        entity_id=profile.id,
        after=profile_state(profile),
        source_ip=client_ip(request),
    )
    db.commit()
    return RedirectResponse(url="/profiles", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/profiles/{profile_id}/edit", response_class=HTMLResponse)
def edit_profile_page(
    profile_id: uuid.UUID,
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    profile = db.get(TrapProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    return render_profile_form(request, context, profile_to_form(profile), profile=profile)


@router.post("/profiles/{profile_id}/edit", response_class=HTMLResponse)
def update_profile_page(
    profile_id: uuid.UUID,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    interaction_level: str = Form(...),
    services_json: str = Form(...),
    bait_credentials_json: str = Form(...),
    logging_json: str = Form(...),
    masking_json: str = Form(...),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    profile = db.get(TrapProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    form = locals().copy()
    try:
        payload = parse_profile_form(form)
    except (ValidationError, ValueError) as exc:
        return render_profile_form(request, context, form, profile=profile, error=str(exc), code=422)
    before = profile_state(profile)
    for key, value in payload.model_dump(mode="json").items():
        setattr(profile, key, value)
    profile.config_version += 1
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return render_profile_form(request, context, form, profile=profile, error="Имя уже занято.", code=409)
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
    return RedirectResponse(url="/profiles", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/profiles/{profile_id}/delete")
def delete_profile_page(
    profile_id: uuid.UUID,
    request: Request,
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
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
        raise HTTPException(status_code=409, detail="Профиль используется ловушкой") from exc
    return RedirectResponse(url="/profiles", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/hosts", response_class=HTMLResponse)
def hosts_page(
    request: Request,
    context: AuthContext = Depends(get_ui_auth_context),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    hosts = list(db.scalars(select(Host).options(selectinload(Host.instances)).order_by(Host.name)))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="hosts.html",
        context=base_context(context, hosts=hosts),
    )


@router.get("/hosts/enroll", response_class=HTMLResponse)
def enrollment_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    profiles = list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="enrollment.html",
        context=base_context(context, profiles=profiles, token=None, error=None),
    )


@router.post("/hosts/enroll", response_class=HTMLResponse)
def create_enrollment_page(
    request: Request,
    host_name: str = Form(...),
    management_address: str = Form(...),
    instance_name: str = Form(...),
    profile_id: uuid.UUID = Form(...),
    ttl_minutes: int = Form(15),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    profiles = list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))
    try:
        validated = HostInput(name=host_name, management_address=management_address, description="")
        if ttl_minutes < 1 or ttl_minutes > 60:
            raise ValueError("Срок действия должен быть от 1 до 60 минут")
        profile = db.get(TrapProfile, profile_id)
        if not profile:
            raise ValueError("Профиль не найден")
        host = Host(name=validated.name, management_address=validated.management_address, description="", status=HostStatus.OFFLINE)
        instance = HoneypotInstance(name=instance_name, host=host, profile=profile, status=TrapStatus.PENDING)
        raw_token = secrets.token_urlsafe(48)
        expires_at = utcnow() + timedelta(minutes=ttl_minutes)
        enrollment = EnrollmentToken(
            host=host,
            token_hash=token_hash(raw_token),
            expires_at=expires_at,
            created_by_id=context.user.id,
        )
        db.add_all([host, instance, enrollment])
        db.flush()
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
    except (ValidationError, ValueError, IntegrityError) as exc:
        db.rollback()
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="enrollment.html",
            context=base_context(context, profiles=profiles, token=None, error=str(exc)),
            status_code=422,
        )
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="enrollment.html",
        context=base_context(context, profiles=profiles, token=raw_token, expires_at=expires_at, host=host, instance=instance, error=None),
    )


@router.get("/traps", response_class=HTMLResponse)
def traps_page(
    request: Request,
    context: AuthContext = Depends(get_ui_auth_context),
    db: Session = Depends(get_db),
):
    mark_stale_hosts_offline(db)
    traps = list(
        db.scalars(
            select(HoneypotInstance)
            .options(selectinload(HoneypotInstance.host), selectinload(HoneypotInstance.profile))
            .order_by(HoneypotInstance.name)
        )
    )
    trap_statuses = {trap.id: trap_status_view(trap) for trap in traps}
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="traps.html",
        context=base_context(context, traps=traps, trap_statuses=trap_statuses),
    )


@router.get("/traps/new", response_class=HTMLResponse)
def new_trap_page(
    request: Request,
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    profiles = list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="trap_form.html",
        context=base_context(context, hosts=hosts, profiles=profiles, form={}, error=None),
    )


@router.post("/traps/new", response_class=HTMLResponse)
def create_trap_page(
    request: Request,
    name: str = Form(...),
    host_id: uuid.UUID = Form(...),
    profile_id: uuid.UUID = Form(...),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    profiles = list(db.scalars(select(TrapProfile).order_by(TrapProfile.name)))
    form = {"name": name, "host_id": str(host_id), "profile_id": str(profile_id)}
    try:
        payload = TrapInstanceCreate(name=name, host_id=host_id, profile_id=profile_id)
        host = db.get(Host, payload.host_id)
        profile = db.get(TrapProfile, payload.profile_id)
        if not host:
            raise ValueError("Хост не найден")
        if not profile:
            raise ValueError("Профиль не найден")
        ensure_profile_ports_available(db, host.id, profile)
        instance = HoneypotInstance(
            name=payload.name,
            host=host,
            profile=profile,
            status=TrapStatus.PENDING,
        )
        db.add(instance)
        db.flush()
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
    except (ValidationError, ValueError, IntegrityError) as exc:
        db.rollback()
        message = "Имя экземпляра уже используется" if isinstance(exc, IntegrityError) else str(exc)
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="trap_form.html",
            context=base_context(context, hosts=hosts, profiles=profiles, form=form, error=message),
            status_code=422,
        )
    return RedirectResponse(url="/traps", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/traps/{trap_id}/action")
def trap_action(
    trap_id: uuid.UUID,
    request: Request,
    command: str = Form(...),
    csrf_token: str = Form(...),
    context: AuthContext = Depends(require_ui_roles(*writers)),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    if command not in ALLOWED_TRAP_COMMANDS:
        raise HTTPException(status_code=422, detail="Unsupported trap action")
    instance = db.get(HoneypotInstance, trap_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Trap not found")
    create_trap_job(
        db,
        instance=instance,
        command=command,
        actor=context.user,
        source_ip=client_ip(request),
    )
    db.commit()
    return RedirectResponse(url="/traps", status_code=status.HTTP_303_SEE_OTHER)
