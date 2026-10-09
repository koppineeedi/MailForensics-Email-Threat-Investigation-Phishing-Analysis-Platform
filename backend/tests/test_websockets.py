from fastapi.testclient import TestClient

def test_websocket_connection(client: TestClient):
    with client.websocket_connect("/ws/email/test_ws_email_id") as websocket:
        # Verify socket connection connects without throwing exception
        pass
