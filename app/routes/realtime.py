from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select

from app.database import SessionLocal
from app.event_view import can_view_sensitive_event_data, redact_event_data
from app.models import Event, User, UserRole, UserSession, utcnow
from app.realtime import event_manager
from app.schemas import EventRead
from app.security import COOKIE_NAME, token_hash

router = APIRouter(tags=["realtime"])


def authorized_websocket(websocket: WebSocket) -> UserRole | None:
    raw_token = websocket.cookies.get(COOKIE_NAME)
    if not raw_token:
        return None
    with SessionLocal() as db:
        session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(raw_token)))
        if not session:
            return None
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        user = db.get(User, session.user_id)
        if expires_at <= utcnow() or not user or not user.is_active:
            return None
        return user.role


@router.websocket("/ws/events")
async def event_feed(websocket: WebSocket):
    role = authorized_websocket(websocket)
    if role is None:
        await websocket.close(code=4401)
        return
    allow_sensitive = can_view_sensitive_event_data(role)
    since_raw = websocket.query_params.get("since")
    since: datetime | None = None
    if since_raw:
        try:
            since = datetime.fromisoformat(since_raw.replace("Z", "+00:00"))
        except ValueError:
            await websocket.close(code=4400)
            return
    await event_manager.connect(websocket, allow_sensitive=allow_sensitive)
    try:
        with SessionLocal() as db:
            query = select(Event)
            if since:
                query = query.where(Event.created_at >= since)
            backlog = list(db.scalars(query.order_by(Event.created_at).limit(500)))
        for event in backlog:
            visible = EventRead.model_validate(event).model_copy(
                update={
                    "data": redact_event_data(
                        event.data or {}, allow_sensitive=allow_sensitive
                    )
                }
            )
            await websocket.send_json(jsonable_encoder(visible))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        event_manager.disconnect(websocket)
    except Exception:
        event_manager.disconnect(websocket)
        raise
