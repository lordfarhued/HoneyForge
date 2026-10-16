from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path

from agent.config import AgentSettings
from agent.queue import DurableQueue

logger = logging.getLogger("runtime-worker")


class UnknownEventInstance(ValueError):
    pass


class EngineController:
    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self.config_files = {
            "low": Path(settings.low_config_file),
            "medium": Path(settings.medium_config_file),
            "high": Path(settings.high_config_file),
        }
        self.event_directories = {
            "low": Path(settings.low_event_dir),
            "medium": Path(settings.medium_event_dir),
            "high": Path(settings.high_event_dir),
        }
        for path in [*self.config_files.values(), *self.event_directories.values()]:
            (path.parent if path.suffix else path).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _atomic_write(path: Path, payload: dict) -> bool:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if path.exists() and path.read_bytes() == encoded:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return True

    def render(self, queue: DurableQueue) -> dict[str, bool]:
        grouped: dict[str, list[dict]] = {"low": [], "medium": [], "high": []}
        for config in queue.configurations():
            level = config.get("profile", {}).get("interaction_level")
            if level not in grouped:
                continue
            profile = config["profile"]
            grouped[level].append(
                {
                    "instance_id": config["instance_id"],
                    "instance_name": config["instance_name"],
                    "config_version": profile["config_version"],
                    "enabled": queue.engine_enabled(config["instance_id"]),
                    "services": profile["services"],
                    "bait_credentials": profile.get("bait_credentials", []),
                    "logging": profile.get("logging", {}),
                    "masking": profile.get("masking", {}),
                }
            )
        return {
            level: self._atomic_write(
                self.config_files[level],
                {"schema_version": 1, "interaction_level": level, "instances": instances},
            )
            for level, instances in grouped.items()
        }

    def read_statuses(self, queue: DurableQueue) -> list[dict]:
        known = {item["instance_id"] for item in queue.configurations()}
        statuses: list[dict] = []
        for level, directory in self.event_directories.items():
            path = directory / "status.json"
            if not path.exists():
                continue
            try:
                if path.stat().st_size > 65_536:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
                if payload.get("engine") != level or not isinstance(payload.get("instances"), dict):
                    continue
                for instance_id, status in payload["instances"].items():
                    if instance_id not in known or status.get("state") not in ("online", "offline", "error"):
                        continue
                    endpoints = status.get("endpoints", [])
                    if not isinstance(endpoints, list):
                        endpoints = []
                    statuses.append(
                        {
                            "instance_id": instance_id,
                            "state": status["state"],
                            "config_version": int(status.get("config_version", 0)),
                            "details": {
                                "engine": level,
                                "ports": status.get("ports", [])[:32],
                                "endpoints": endpoints[:32],
                                "error": str(status.get("error"))[:240] if status.get("error") else None,
                            },
                        }
                    )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                logger.warning("Ignored invalid %s engine status", level)
        return statuses

    def _validated_event(self, level: str, raw: bytes, allowed: set[str]) -> dict:
        if len(raw) > 65_536:
            raise ValueError("event file too large")
        event = json.loads(raw)
        uuid.UUID(str(event["external_id"]))
        instance_id = str(uuid.UUID(str(event["instance_id"])))
        if instance_id not in allowed:
            raise UnknownEventInstance("event references unknown instance")
        event_type = str(event["event_type"])
        if not event_type.startswith(f"{level}.") or len(event_type) > 80:
            raise ValueError("event type is invalid")
        source_ip = event.get("source_ip")
        if source_ip is not None:
            source_ip = str(ipaddress.ip_address(source_ip))
        occurred = datetime.fromisoformat(str(event["occurred_at"]).replace("Z", "+00:00"))
        if occurred.tzinfo is None or occurred.utcoffset() is None:
            raise ValueError("event timestamp lacks timezone")
        data = event.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("event data is not an object")
        if len(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 16_384:
            raise ValueError("event data too large")
        return {
            "external_id": str(event["external_id"]),
            "instance_id": instance_id,
            "event_type": event_type,
            "source_ip": source_ip,
            "occurred_at": occurred.isoformat(),
            "data": data,
            "is_test": False,
        }

    def ingest_events(self, queue: DurableQueue) -> int:
        allowed_by_level: dict[str, set[str]] = {"low": set(), "medium": set(), "high": set()}
        for config in queue.configurations():
            level = config.get("profile", {}).get("interaction_level")
            if level in allowed_by_level:
                allowed_by_level[level].add(config["instance_id"])
        ingested = 0
        for level, directory in self.event_directories.items():
            for path in sorted(directory.glob("*.event.json"))[:500]:
                try:
                    event = self._validated_event(level, path.read_bytes(), allowed_by_level[level])
                    if not queue.enqueue(event):
                        logger.warning("Durable event queue is full; leaving engine events in the spool")
                        return ingested
                    path.unlink()
                    ingested += 1
                except UnknownEventInstance:
                    # A persisted engine configuration can produce telemetry
                    # before a restarted agent has downloaded its configuration.
                    # Keep the bounded spool file and retry after the next sync.
                    logger.info("Deferred event from %s engine until its configuration is available", level)
                except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError):
                    logger.warning("Rejected invalid event from %s engine", level)
                    try:
                        path.unlink()
                    except OSError:
                        pass
        return ingested

    def _status_for(self, queue: DurableQueue, instance_id: str) -> dict | None:
        return next((item for item in self.read_statuses(queue) if item["instance_id"] == instance_id), None)

    def _wait_for(
        self,
        queue: DurableQueue,
        instance_id: str,
        state: str,
        version: int,
        not_before: float | None,
    ) -> dict:
        deadline = time.monotonic() + self.settings.engine_apply_timeout
        config = queue.configuration(instance_id)
        level = config["profile"]["interaction_level"] if config else None
        status_path = self.event_directories.get(level, Path("/nonexistent")) / "status.json"
        while time.monotonic() < deadline:
            status = self._status_for(queue, instance_id)
            fresh = not_before is None or (
                status_path.exists() and status_path.stat().st_mtime >= not_before
            )
            if status and fresh and status["config_version"] == version:
                if status["state"] == state:
                    return status
                if status["state"] == "error":
                    raise RuntimeError(status["details"].get("error") or "engine reported an error")
            time.sleep(0.2)
        raise TimeoutError(f"engine did not reach {state} state")

    def execute_job(self, queue: DurableQueue, job: dict) -> tuple[str, dict]:
        command = job["command"]
        if command == "collect_status":
            return "succeeded", {"statuses": self.read_statuses(queue)}
        if command not in ("apply_config", "start_trap", "stop_trap"):
            return "failed", {"reason": "unsupported_command"}
        instance_id = str(job.get("instance_id") or "")
        config = queue.configuration(instance_id)
        if not config:
            return "failed", {"reason": "configuration_not_found"}
        level = config["profile"]["interaction_level"]
        if level not in ("low", "medium", "high"):
            return "failed", {"reason": "unsupported_interaction_level"}
        if command == "start_trap":
            queue.set_engine_enabled(instance_id, True)
            expected = "online"
        elif command == "stop_trap":
            queue.set_engine_enabled(instance_id, False)
            expected = "offline"
        else:
            expected = "online" if queue.engine_enabled(instance_id) else "offline"
        changed_at = time.time()
        rendered = self.render(queue)
        try:
            status = self._wait_for(
                queue,
                instance_id,
                expected,
                int(config["profile"]["config_version"]),
                changed_at if command in ("start_trap", "stop_trap") and rendered[level] else None,
            )
        except (OSError, RuntimeError, TimeoutError) as exc:
            return "failed", {"reason": type(exc).__name__, "message": str(exc)[:240]}
        return "succeeded", {
            "instance_id": instance_id,
            "state": status["state"],
            "config_version": status["config_version"],
            "engine": level,
            "ports": status["details"]["ports"],
            "endpoints": status["details"]["endpoints"],
        }
