from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import HoneypotInstance, Host, HostStatus, TrapStatus, utcnow


@dataclass(frozen=True)
class TrapStatusView:
    status: str
    reported_status: TrapStatus
    host_status: HostStatus
    status_stale: bool


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def status_cutoff(now: datetime | None = None) -> datetime:
    current = _aware_utc(now) if now else utcnow()
    return current - timedelta(seconds=get_settings().agent_offline_after_seconds)


def mark_stale_hosts_offline(db: Session, *, now: datetime | None = None) -> None:
    cutoff = status_cutoff(now)
    result = db.execute(
        update(Host)
        .where(
            Host.status != HostStatus.OFFLINE,
            or_(Host.last_seen_at.is_(None), Host.last_seen_at < cutoff),
        )
        .values(status=HostStatus.OFFLINE)
    )
    if result.rowcount:
        db.commit()


def trap_status_view(instance: HoneypotInstance, *, now: datetime | None = None) -> TrapStatusView:
    """Separate the last engine report from what the center can currently verify."""
    reported = instance.status
    host = instance.host
    cutoff = status_cutoff(now)
    host_report_fresh = bool(
        host.status == HostStatus.ONLINE
        and host.last_seen_at is not None
        and _aware_utc(host.last_seen_at) >= cutoff
    )
    trap_report_fresh = bool(
        instance.last_seen_at is not None
        and _aware_utc(instance.last_seen_at) >= cutoff
    )

    if reported == TrapStatus.PENDING:
        effective = TrapStatus.PENDING.value
    elif host_report_fresh and trap_report_fresh:
        effective = reported.value
    else:
        effective = "unknown"
    return TrapStatusView(
        status=effective,
        reported_status=reported,
        host_status=host.status,
        status_stale=effective == "unknown",
    )
