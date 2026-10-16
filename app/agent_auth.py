from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import timezone
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.models import AgentIdentity, Host, utcnow


def peer_address_matches(host: str, peer_name: str) -> bool:
    try:
        source = ipaddress.ip_address(host.split("%", 1)[0])
        addresses = {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(peer_name, None, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return False
    return source in addresses


def require_agent_gateway(request: Request) -> None:
    settings = get_settings()
    peer = request.client.host if request.client else ""
    if not (settings.environment == "test" and peer == "testclient") and not peer_address_matches(
        peer, settings.agent_gateway_peer_name
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if request.headers.get("x-honeyforge-gateway") != "agent-gateway":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if request.headers.get("x-forwarded-proto") != "https":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TLS is required")


@dataclass
class AgentContext:
    identity: AgentIdentity
    host: Host


def get_agent_context(request: Request, db: Session = Depends(get_db)) -> AgentContext:
    require_agent_gateway(request)
    if request.headers.get("x-honeyforge-client-verify") != "SUCCESS":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid client certificate required")
    escaped_cert = request.headers.get("x-honeyforge-client-cert")
    if not escaped_cert:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client certificate missing")
    try:
        certificate = x509.load_pem_x509_certificate(unquote(escaped_cert).encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client certificate") from exc

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    serial = format(certificate.serial_number, "x")
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.certificate_fingerprint_sha256 == fingerprint,
            AgentIdentity.certificate_serial == serial,
        )
    )
    if not identity or identity.status != "active" or identity.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent identity is not active")
    expires_at = identity.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent certificate expired")
    host = db.get(Host, identity.host_id)
    if not host:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent host no longer exists")
    return AgentContext(identity=identity, host=host)
