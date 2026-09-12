#![forbid(unsafe_code)]

mod media;

use std::sync::Arc;

use axum::{routing::get, Router};
use tokio::sync::mpsc;
use wroom_signaling::auth::DevTokenVerifier;
use wroom_signaling::media::MediaSink;
use wroom_signaling::ws::Hub;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,wroomd=debug,wroom_edge=debug,wroom_signaling=debug".into()),
        )
        .init();

    // Shared signaling state: the room registry plus per-session outbound
    // channels, serialized by a Mutex inside `Hub`. That is the control
    // plane — joins, publishes, subscription updates — where message
    // volume is trivial. It is explicitly NOT the media hot path, where
    // the AGENTS/D12 lock-free rules apply; media never touches it.
    //
    // D16 dev auth: plaintext `room_id:display_name` tokens behind the
    // `TokenVerifier` interface until a real provider lands.
    let mut hub = Hub::new(Arc::new(DevTokenVerifier));

    // The media plane: one UDP socket + transports + forwarding, running
    // as a single task fed by a control channel from signaling.
    let (media_tx, media_rx) = mpsc::unbounded_channel();
    hub.set_media(MediaSink(media_tx));
    let advertise = std::env::var("WROOM_ADVERTISE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    let media_port: u16 = std::env::var("WROOM_MEDIA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10000);
    tokio::spawn(async move {
        if let Err(e) = media::run(media_rx, media_port, advertise).await {
            tracing::error!(error = %e, "media plane exited");
        }
    });
    let hub = Arc::new(hub);

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
