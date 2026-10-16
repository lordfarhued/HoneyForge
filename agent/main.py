from __future__ import annotations

import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent.client import AgentClient
from agent.config import AgentSettings
from agent.engines import EngineController
from agent.pki import ensure_key_and_csr
from agent.queue import DurableQueue
from agent.runtime_masking import select_profile_value, set_process_name

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("runtime-worker")


def ensure_enrolled(settings: AgentSettings, client: AgentClient, state: Path) -> None:
    if client.cert_path.exists():
        return
    token_path = Path(settings.enrollment_token_file)
    if not token_path.exists() or not token_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("Enrollment token file is missing or empty")
    csr_path = client.identity_paths.csr
    identity_path = client.identity_paths.metadata
    csr = ensure_key_and_csr(client.key_path, csr_path)
    response = client.enroll(token_path.read_text(encoding="utf-8").strip(), csr)
    client.cert_path.write_text(response["certificate_pem"], encoding="ascii")
    client.activate_identity()
    identity_path.write_text(
        json.dumps(
            {
                "identity_id": response["identity_id"],
                "host_id": response["host_id"],
                "certificate_expires_at": response["certificate_expires_at"],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    try:
        token_path.unlink()
    except OSError:
        logger.warning("Enrollment completed, but the one-time token file could not be removed")
    logger.info("Runtime enrollment completed")


def sync_configuration(client: AgentClient, queue: DurableQueue) -> list[dict]:
    response = client.configuration()
    configurations = response["configurations"]
    for item in configurations:
        changed = queue.store_configuration(
            item["instance_id"], item["profile"]["config_version"], item
        )
        if changed:
            logger.info("Configuration updated for instance %s to version %s", item["instance_id"], item["profile"]["config_version"])
    queue.remove_stale_configurations({item["instance_id"] for item in configurations})
    return configurations


def sync_jobs(client: AgentClient, queue: DurableQueue, engines: EngineController) -> None:
    for job in client.jobs():
        stored = queue.get_job_result(job["id"])
        if stored:
            state, result = stored
        else:
            state, result = engines.execute_job(queue, job)
            queue.store_job_result(job["id"], state, result)
        client.acknowledge_job(job["id"], state, result)


def enqueue_synthetic(queue: DurableQueue, configurations: list[dict]) -> None:
    if not configurations:
        return
    event = {
        "external_id": str(uuid.uuid4()),
        "instance_id": configurations[0]["instance_id"],
        "event_type": "agent.synthetic_test",
        "source_ip": "192.0.2.1",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": {"origin": "synthetic_local_agent", "description": "explicit stage-2 delivery test"},
        "is_test": True,
    }
    queue.enqueue(event)


def flush_events(client: AgentClient, queue: DurableQueue, batch_size: int) -> None:
    pending = queue.pending(batch_size)
    if not pending:
        return
    ack = client.send_events(pending)
    acknowledged = [*ack["accepted_ids"], *ack["duplicate_ids"]]
    queue.acknowledge(acknowledged)
    logger.info("Event batch acknowledged: %d", len(acknowledged))


def heartbeat_delay(settings: AgentSettings, uniform=random.uniform) -> float:
    ratio = settings.heartbeat_jitter_ratio
    return settings.heartbeat_seconds * uniform(1 - ratio, 1 + ratio)


def apply_runtime_masking(settings: AgentSettings, configurations: list[dict]) -> str:
    process_name = select_profile_value(configurations, "process_name", settings.process_name)
    selected_path = select_profile_value(configurations, "install_path", settings.install_path)
    if selected_path != settings.install_path:
        logger.warning("Configured runtime location requires a matching deployment build")
    return set_process_name(process_name)


def run() -> None:
    settings = AgentSettings()
    set_process_name(settings.process_name)
    state = Path(settings.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    queue = DurableQueue(str(state / "queue.sqlite3"), max_events=settings.queue_max_events)
    client = AgentClient(settings)
    engines = EngineController(settings)
    engines.render(queue)
    attempt = 0
    last_synthetic = 0.0
    try:
        while True:
            ingested = engines.ingest_events(queue)
            if ingested:
                logger.info("Moved %d engine events into the durable queue", ingested)
            if settings.synthetic_interval > 0 and time.monotonic() - last_synthetic >= settings.synthetic_interval:
                enqueue_synthetic(queue, queue.configurations())
                last_synthetic = time.monotonic()
            try:
                ensure_enrolled(settings, client, state)
                client.heartbeat(queue.depth())
                configurations = sync_configuration(client, queue)
                apply_runtime_masking(settings, configurations)
                engines.render(queue)
                sync_jobs(client, queue, engines)
                client.report_status(engines.read_statuses(queue))
                flush_events(client, queue, settings.batch_size)
                (state / "last_success").touch()
                attempt = 0
                delay = heartbeat_delay(settings)
            except Exception as exc:
                attempt += 1
                ceiling = min(settings.retry_max_seconds, 1.5 * (2 ** min(attempt, 8)))
                delay = random.uniform(0.5, ceiling)
                logger.warning("Runtime cycle failed (%s); retrying in %.1fs", type(exc).__name__, delay)
            time.sleep(delay)
    finally:
        client.close()


if __name__ == "__main__":
    run()
