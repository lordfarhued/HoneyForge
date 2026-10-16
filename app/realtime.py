from __future__ import annotations

from fastapi import WebSocket

from app.event_view import redact_event_data


class EventConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, bool] = {}

    async def connect(self, websocket: WebSocket, *, allow_sensitive: bool) -> None:
        await websocket.accept()
        self._connections[websocket] = allow_sensitive

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.pop(websocket, None)

    async def broadcast(self, payload: dict) -> None:
        stale: list[WebSocket] = []
        for websocket, allow_sensitive in tuple(self._connections.items()):
            try:
                visible_payload = {
                    **payload,
                    "data": redact_event_data(
                        payload.get("data", {}), allow_sensitive=allow_sensitive
                    ),
                }
                await websocket.send_json(visible_payload)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)


event_manager = EventConnectionManager()
