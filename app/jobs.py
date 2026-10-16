from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.models import HoneypotInstance, Job, TrapProfile, User


ALLOWED_TRAP_COMMANDS = frozenset({"apply_config", "start_trap", "stop_trap", "collect_status"})


def create_trap_job(
    db: Session,
    *,
    instance: HoneypotInstance,
    command: str,
    payload: dict | None = None,
    actor: User | None,
    source_ip: str | None,
    idempotency_key: str | None = None,
) -> Job:
    if command not in ALLOWED_TRAP_COMMANDS:
        raise ValueError("unsupported trap command")
    job_payload = payload or {}
    if len(json.dumps(job_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 8192:
        raise ValueError("job payload exceeds 8 KiB")
    key = idempotency_key or f"operator:{command}:{instance.id}:{uuid.uuid4()}"
    existing = db.scalar(select(Job).where(Job.idempotency_key == key))
    if existing:
        return existing
    job = Job(
        host_id=instance.host_id,
        instance_id=instance.id,
        command=command,
        payload=job_payload,
        state="pending",
        idempotency_key=key,
    )
    db.add(job)
    db.flush()
    write_audit(
        db,
        actor=actor,
        action="trap.job_created",
        entity_type="job",
        entity_id=job.id,
        after={"instance_id": instance.id, "command": command},
        source_ip=source_ip,
    )
    return job


def enqueue_profile_application(
    db: Session,
    *,
    profile: TrapProfile,
    actor: User | None,
    source_ip: str | None,
) -> list[Job]:
    instances = list(db.scalars(select(HoneypotInstance).where(HoneypotInstance.profile_id == profile.id)))
    return [
        create_trap_job(
            db,
            instance=instance,
            command="apply_config",
            payload={"config_version": profile.config_version},
            actor=actor,
            source_ip=source_ip,
            idempotency_key=f"apply:{instance.id}:v{profile.config_version}",
        )
        for instance in instances
    ]
