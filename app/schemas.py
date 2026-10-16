from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.models import HostStatus, InteractionLevel, TrapStatus, UserRole


class ServiceConfig(BaseModel):
    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9._-]+$")
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    banner: str = Field(default="", max_length=500)

    @field_validator("banner")
    @classmethod
    def safe_banner(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("banner must not contain line breaks")
        return value


class BaitCredential(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=128)


class LoggingConfig(BaseModel):
    capture_connections: bool = True
    capture_credentials: bool = True
    capture_commands: bool = True
    capture_payloads: bool = False


class MaskingConfig(BaseModel):
    endpoint_path: str = Field(default="/assets/telemetry", pattern=r"^/[a-zA-Z0-9/_-]+$")
    process_name: str = Field(default="system-metrics", min_length=3, max_length=64)
    install_path: str = Field(default="/opt/system-metrics", pattern=r"^/[a-zA-Z0-9/._-]+$")
    response_delay_ms: int = Field(default=0, ge=0, le=2000)


class ProfileInput(BaseModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[\w .-]+$")
    description: str = Field(default="", max_length=2000)
    interaction_level: InteractionLevel
    services: list[ServiceConfig] = Field(min_length=1, max_length=32)
    bait_credentials: list[BaitCredential] = Field(default_factory=list, max_length=32)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    masking: MaskingConfig = Field(default_factory=MaskingConfig)

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def unique_ports(self):
        endpoints = [(item.protocol, item.port) for item in self.services]
        if len(endpoints) != len(set(endpoints)):
            raise ValueError("Пары protocol/port в профиле должны быть уникальны")
        if self.interaction_level == InteractionLevel.HIGH:
            names = [item.name.lower() for item in self.services]
            if len(self.services) != 2 or set(names) != {"http", "ssh"}:
                raise ValueError("High-профиль должен содержать ровно сервисы http и ssh")
            if any(item.protocol != "tcp" for item in self.services):
                raise ValueError("High HTTP и SSH поддерживают только протокол tcp")
        return self


class ProfileRead(ProfileInput):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    config_version: int


class HostInput(BaseModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[\w .-]+$")
    management_address: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)

    @field_validator("management_address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        value = value.strip()
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value):
                raise ValueError("Укажите корректный IP-адрес или DNS-имя")
            return value.lower()


class HostRead(HostInput):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: HostStatus
    last_seen_at: datetime | None
    created_at: datetime


class TrapRead(BaseModel):
    id: uuid.UUID
    name: str
    host_id: uuid.UUID
    profile_id: uuid.UUID
    status: Literal["pending", "offline", "online", "error", "unknown"]
    reported_status: TrapStatus
    host_status: HostStatus
    status_stale: bool
    last_seen_at: datetime | None
    created_at: datetime


class TrapInstanceCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[\w .-]+$")
    host_id: uuid.UUID
    profile_id: uuid.UUID

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        return value.strip()


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool


class SessionInfo(BaseModel):
    user: UserRead
    csrf_token: str


class EnrollmentCreate(BaseModel):
    host_name: str = Field(min_length=3, max_length=80, pattern=r"^[\w .-]+$")
    management_address: str = Field(min_length=1, max_length=255)
    instance_name: str = Field(min_length=3, max_length=80, pattern=r"^[\w .-]+$")
    profile_id: uuid.UUID
    ttl_minutes: int = Field(default=15, ge=1, le=60)


class EnrollmentCreated(BaseModel):
    host_id: uuid.UUID
    instance_id: uuid.UUID
    enrollment_token: str
    expires_at: datetime


class AgentEnrollmentRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    csr_pem: str = Field(min_length=200, max_length=8192)
    agent_version: str = Field(min_length=1, max_length=40)


class AgentEnrollmentResponse(BaseModel):
    identity_id: uuid.UUID
    host_id: uuid.UUID
    certificate_pem: str
    certificate_expires_at: datetime


class AgentHeartbeat(BaseModel):
    agent_version: str = Field(min_length=1, max_length=40)
    queue_depth: int = Field(ge=0, le=1_000_000)


class AgentProfileConfig(BaseModel):
    instance_id: uuid.UUID
    instance_name: str
    profile: ProfileRead


class AgentConfigResponse(BaseModel):
    host_id: uuid.UUID
    configurations: list[AgentProfileConfig]


class EventInput(BaseModel):
    external_id: uuid.UUID
    instance_id: uuid.UUID
    event_type: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    source_ip: str | None = Field(default=None, max_length=64)
    occurred_at: datetime
    data: dict = Field(default_factory=dict)
    is_test: bool = False

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def validate_serialized_size(self):
        if len(json.dumps(self.data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 16_384:
            raise ValueError("event data exceeds 16 KiB")
        return self


class EventBatch(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_batch_size(self):
        size = len(self.model_dump_json().encode("utf-8"))
        if size > 524_288:
            raise ValueError("event batch exceeds 512 KiB")
        ids = [item.external_id for item in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("event IDs within a batch must be unique")
        return self


class EventBatchAck(BaseModel):
    accepted_ids: list[uuid.UUID]
    duplicate_ids: list[uuid.UUID]


class EventRead(EventInput):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    instance_id: uuid.UUID | None
    command: str
    payload: dict
    state: str
    idempotency_key: str


class TrapJobCreate(BaseModel):
    command: Literal["apply_config", "start_trap", "stop_trap", "collect_status"]
    payload: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_payload_size(self):
        if len(json.dumps(self.payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 8192:
            raise ValueError("job payload exceeds 8 KiB")
        return self


class AgentTrapStatus(BaseModel):
    instance_id: uuid.UUID
    state: Literal["online", "offline", "error"]
    config_version: int = Field(ge=0)
    details: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_details_size(self):
        if len(json.dumps(self.details, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 4096:
            raise ValueError("status details exceed 4 KiB")
        return self


class AgentStatusReport(BaseModel):
    statuses: list[AgentTrapStatus] = Field(default_factory=list, max_length=64)


class JobAck(BaseModel):
    state: Literal["acknowledged", "succeeded", "failed"]
    result: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_result_size(self):
        if len(json.dumps(self.result, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 8192:
            raise ValueError("job result exceeds 8 KiB")
        return self


class RotateCertificateRequest(BaseModel):
    csr_pem: str = Field(min_length=200, max_length=8192)


class RotateCertificateResponse(BaseModel):
    certificate_pem: str
    certificate_expires_at: datetime
