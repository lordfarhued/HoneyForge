from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.models import AuditEntry, User


def write_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    entity_type: str,
    entity_id: Any = None,
    before: Any = None,
    after: Any = None,
    source_ip: str | None = None,
) -> None:
    db.add(
        AuditEntry(
            actor_id=actor.id if actor else None,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            before_state=jsonable_encoder(before) if before is not None else None,
            after_state=jsonable_encoder(after) if after is not None else None,
            source_ip=source_ip,
        )
    )
