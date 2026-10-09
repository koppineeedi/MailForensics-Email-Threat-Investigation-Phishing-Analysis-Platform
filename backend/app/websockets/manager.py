import json
from typing import Dict, List
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # email_id -> List[WebSocket]
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Global audit log subscribers
        self.audit_connections: List[WebSocket] = []

    async def connect_email(self, email_id: str, websocket: WebSocket):
        await websocket.accept()
        if email_id not in self.active_connections:
            self.active_connections[email_id] = []
        self.active_connections[email_id].append(websocket)

    def disconnect_email(self, email_id: str, websocket: WebSocket):
        if email_id in self.active_connections:
            if websocket in self.active_connections[email_id]:
                self.active_connections[email_id].remove(websocket)
            if not self.active_connections[email_id]:
                del self.active_connections[email_id]

    async def broadcast_email_event(self, email_id: str, event_data: dict):
        """Broadcast real backend event to subscribers of specific email_id."""
        if email_id in self.active_connections:
            message = json.dumps(event_data, default=str)
            for connection in self.active_connections[email_id]:
                try:
                    await connection.send_text(message)
                except Exception:
                    pass

    async def connect_audit(self, websocket: WebSocket):
        await websocket.accept()
        self.audit_connections.append(websocket)

    def disconnect_audit(self, websocket: WebSocket):
        if websocket in self.audit_connections:
            self.audit_connections.remove(websocket)

    async def broadcast_audit_event(self, event_data: dict):
        """Broadcast live audit log events."""
        message = json.dumps(event_data, default=str)
        for connection in self.audit_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()
