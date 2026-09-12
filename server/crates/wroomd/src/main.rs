#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{routing::get, Router};
use wroom_signaling::auth::DevTokenVerifier;
use wroom_signaling::ws::Hub;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Shared signaling state: the room registry plus per-session outbound
    // channels, serialized by a Mutex inside `Hub`. That is the control
    // plane — joins, publishes, subscription updates — where message
    // volume is trivial. It is explicitly NOT the media hot path, where
    // the AGENTS/D12 lock-free rules apply; media never touches it.
    //
    // D16 dev auth: plaintext `room_id:display_name` tokens behind the
    // `TokenVerifier` interface until a real provider lands.
    let hub = Arc::new(Hub::new(Arc::new(DevTokenVerifier)));

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(wroom_signaling::ws::handler))
        .with_state(hub);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind");
    tracing::info!(addr = %listener.local_addr().unwrap(), "listening");
    axum::serve(listener, app).await.expect("serve");
}
