from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.websockets.manager import manager

router = APIRouter(tags=["WebSockets"])

@router.websocket("/ws/email/{email_id}")
async def websocket_email_endpoint(websocket: WebSocket, email_id: str):
    await manager.connect_email(email_id, websocket)
    try:
        while True:
            # Keep connection open for real-time broadcasts
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_email(email_id, websocket)

@router.websocket("/ws/audit")
async def websocket_audit_endpoint(websocket: WebSocket):
    await manager.connect_audit(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_audit(websocket)
