"""Agent enrollment, identities, versioned profiles and event delivery.

Revision ID: 20261009_0002
Revises: 20261009_0001
Create Date: 2026-10-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20261009_0002"
down_revision: Union[str, None] = "20261009_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("trap_profiles", sa.Column("config_version", sa.Integer(), nullable=False, server_default="1"))

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("host_id", sa.Uuid(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_enrollment_tokens_host_id", "enrollment_tokens", ["host_id"])
    op.create_index("ix_enrollment_tokens_token_hash", "enrollment_tokens", ["token_hash"])
    op.create_index("ix_enrollment_tokens_expires_at", "enrollment_tokens", ["expires_at"])

    op.create_table(
        "agent_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("host_id", sa.Uuid(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("certificate_serial", sa.String(64), nullable=False, unique=True),
        sa.Column("certificate_fingerprint_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("public_key_pin_sha256", sa.String(128), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_identities_host_id", "agent_identities", ["host_id"])
    op.create_index("ix_agent_identities_certificate_serial", "agent_identities", ["certificate_serial"])
    op.create_index("ix_agent_identities_certificate_fingerprint_sha256", "agent_identities", ["certificate_fingerprint_sha256"])
    op.create_index("ix_agent_identities_status", "agent_identities", ["status"])
    op.create_index("ix_agent_identities_expires_at", "agent_identities", ["expires_at"])

    op.add_column("events", sa.Column("agent_identity_id", sa.Uuid(), nullable=True))
    op.add_column("events", sa.Column("is_test", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_foreign_key(
        "fk_events_agent_identity_id", "events", "agent_identities", ["agent_identity_id"], ["id"], ondelete="SET NULL"
    )
    op.create_index("ix_events_agent_identity_id", "events", ["agent_identity_id"])
    op.create_index("ix_events_is_test", "events", ["is_test"])

    op.add_column("jobs", sa.Column("result", sa.JSON(), nullable=True))
    op.add_column("jobs", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("jobs", sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("jobs", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("jobs", "acknowledged_at")
    op.drop_column("jobs", "delivered_at")
    op.drop_column("jobs", "attempt_count")
    op.drop_column("jobs", "result")
    op.drop_index("ix_events_is_test", table_name="events")
    op.drop_index("ix_events_agent_identity_id", table_name="events")
    op.drop_constraint("fk_events_agent_identity_id", "events", type_="foreignkey")
    op.drop_column("events", "is_test")
    op.drop_column("events", "agent_identity_id")
    op.drop_table("agent_identities")
    op.drop_table("enrollment_tokens")
    op.drop_column("trap_profiles", "config_version")
