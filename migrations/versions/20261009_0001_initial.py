"""Initial HoneyForge control-center schema.

Revision ID: 20261009_0001
Revises:
Create Date: 2026-10-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20261009_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

uuid_type = sa.Uuid()
timestamp = sa.DateTime(timezone=True)
user_role = sa.Enum("admin", "operator", "observer", name="user_role", native_enum=False)
interaction_level = sa.Enum("low", "medium", "high", name="interaction_level", native_enum=False)
host_status = sa.Enum("offline", "online", "degraded", name="host_status", native_enum=False)
trap_status = sa.Enum("pending", "offline", "online", "error", name="trap_status", native_enum=False)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "user_sessions",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("user_id", uuid_type, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token", sa.String(128), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("expires_at", timestamp, nullable=False),
        sa.Column("last_seen_at", timestamp, nullable=False),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    op.create_table(
        "trap_profiles",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("interaction_level", interaction_level, nullable=False),
        sa.Column("services", sa.JSON(), nullable=False),
        sa.Column("bait_credentials", sa.JSON(), nullable=False),
        sa.Column("logging", sa.JSON(), nullable=False),
        sa.Column("masking", sa.JSON(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_trap_profiles_name", "trap_profiles", ["name"])

    op.create_table(
        "hosts",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("management_address", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=True),
        sa.Column("status", host_status, nullable=False),
        sa.Column("last_seen_at", timestamp, nullable=True),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("agent_id"),
    )

    op.create_table(
        "honeypot_instances",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("host_id", uuid_type, sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("profile_id", uuid_type, sa.ForeignKey("trap_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", trap_status, nullable=False),
        sa.Column("last_seen_at", timestamp, nullable=True),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_honeypot_instances_host_id", "honeypot_instances", ["host_id"])
    op.create_index("ix_honeypot_instances_profile_id", "honeypot_instances", ["profile_id"])

    op.create_table(
        "audit_entries",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("actor_id", uuid_type, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("entity_type", sa.String(80), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("before_state", sa.JSON(), nullable=True),
        sa.Column("after_state", sa.JSON(), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("created_at", timestamp, nullable=False),
    )
    op.create_index("ix_audit_entries_actor_id", "audit_entries", ["actor_id"])
    op.create_index("ix_audit_entries_action", "audit_entries", ["action"])
    op.create_index("ix_audit_entries_entity_type", "audit_entries", ["entity_type"])
    op.create_index("ix_audit_entries_created_at", "audit_entries", ["created_at"])
    op.create_index("ix_audit_entity", "audit_entries", ["entity_type", "entity_id"])

    op.create_table(
        "jobs",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("host_id", uuid_type, sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("instance_id", uuid_type, sa.ForeignKey("honeypot_instances.id", ondelete="CASCADE"), nullable=True),
        sa.Column("command", sa.String(80), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("created_at", timestamp, nullable=False),
        sa.Column("updated_at", timestamp, nullable=False),
    )
    op.create_index("ix_jobs_host_id", "jobs", ["host_id"])
    op.create_index("ix_jobs_instance_id", "jobs", ["instance_id"])
    op.create_index("ix_jobs_state", "jobs", ["state"])

    op.create_table(
        "events",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("external_id", sa.String(128), nullable=False, unique=True),
        sa.Column("instance_id", uuid_type, sa.ForeignKey("honeypot_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("occurred_at", timestamp, nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
    )
    op.create_index("ix_events_external_id", "events", ["external_id"])
    op.create_index("ix_events_instance_id", "events", ["instance_id"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index("ix_events_occurred_at", "events", ["occurred_at"])

    op.create_table(
        "attack_sessions",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("instance_id", uuid_type, sa.ForeignKey("honeypot_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_id", sa.String(128), nullable=False, unique=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("started_at", timestamp, nullable=False),
        sa.Column("ended_at", timestamp, nullable=True),
        sa.Column("recording_path", sa.String(512), nullable=True),
        sa.Column("recording_sha256", sa.String(64), nullable=True),
    )
    op.create_index("ix_attack_sessions_instance_id", "attack_sessions", ["instance_id"])
    op.create_index("ix_attack_sessions_external_id", "attack_sessions", ["external_id"])
    op.create_index("ix_attack_sessions_started_at", "attack_sessions", ["started_at"])

    op.create_table(
        "artifacts",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("event_id", uuid_type, sa.ForeignKey("events.id", ondelete="SET NULL"), nullable=True),
        sa.Column("session_id", uuid_type, sa.ForeignKey("attack_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("kind", sa.String(80), nullable=False),
        sa.Column("storage_path", sa.String(512), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
    )
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_table(
        "honeytokens",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("name", sa.String(80), nullable=False, unique=True),
        sa.Column("token_type", sa.String(40), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
    )

    op.create_table(
        "alerts",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("event_id", uuid_type, sa.ForeignKey("events.id", ondelete="SET NULL"), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", timestamp, nullable=False),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_state", "alerts", ["state"])


def downgrade() -> None:
    for table in [
        "alerts", "honeytokens", "artifacts", "attack_sessions", "events", "jobs",
        "audit_entries", "honeypot_instances", "hosts", "trap_profiles", "user_sessions", "users",
    ]:
        op.drop_table(table)
