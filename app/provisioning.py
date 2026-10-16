from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import HoneypotInstance, TrapProfile


def ensure_profile_ports_available(db: Session, host_id, profile: TrapProfile) -> None:
    """Reject host-local listener collisions before the agent applies config."""
    requested = {
        (str(service.get("protocol", "")), int(service.get("port", 0)))
        for service in profile.services
    }
    instances = db.scalars(
        select(HoneypotInstance)
        .where(HoneypotInstance.host_id == host_id)
        .options(selectinload(HoneypotInstance.profile))
    )
    for instance in instances:
        occupied = {
            (str(service.get("protocol", "")), int(service.get("port", 0)))
            for service in instance.profile.services
        }
        conflicts = requested & occupied
        if conflicts:
            rendered = ", ".join(f"{protocol}/{port}" for protocol, port in sorted(conflicts))
            raise ValueError(f"Host listener already assigned: {rendered}")
