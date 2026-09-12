use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::response::Response;

pub async fn handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle)
}

async fn handle(mut socket: WebSocket) {
    // M0 lands here: decode ClientMessage, drive join/session/subscription flow.
    while let Some(Ok(_)) = socket.recv().await {}
}
