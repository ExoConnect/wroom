#![forbid(unsafe_code)]

mod media;

use std::sync::Arc;

use axum::{routing::get, Router};
use std::net::UdpSocket;
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
    // Comma-separated host candidates — LAN + tailnet addresses can be
    // advertised together; each client keeps whichever pair reaches us.
    // Unset: loopback + the primary outbound address. Loopback alone is
    // a trap — Chrome never enumerates a loopback host candidate, so it
    // pairs interface-bound sockets with 127.0.0.1 and our responses
    // come back with the interface's source addr; the browser drops
    // source-mismatched responses and ICE fails at ~15 s.
    let advertise: Vec<String> = match std::env::var("WROOM_ADVERTISE_ADDR") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => {
            let mut addrs = vec!["127.0.0.1".to_string()];
            if let Ok(s) = UdpSocket::bind("0.0.0.0:0")
                && s.connect("192.0.2.1:80").is_ok()
                && let Ok(a) = s.local_addr()
            {
                addrs.push(a.ip().to_string());
            }
            addrs
        }
    };
    let advertise = if advertise.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        advertise
    };
    let media_port: u16 = std::env::var("WROOM_MEDIA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10000);
    tokio::spawn(async move {
        // Media workers: one shard per ~half the machine, bounded — each
        // shard owns its own UDP socket, so send paths parallelize in
        // the kernel, not just in userspace.
        let shards = std::env::var("WROOM_SHARDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| {
                // Measured: 4 shards ≈ 4× the single-core send ceiling;
                // beyond that the per-packet ring hop costs more than
                // the parallelism saves (flood ladder, media.rs tests).
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .clamp(1, 4)
            });
        if let Err(e) = media::run(media_rx, media_port, advertise, shards).await {
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
