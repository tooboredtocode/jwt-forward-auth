use crate::{State, States};
use axum::extract;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use tracing::info;

async fn healthz() -> impl IntoResponse {
    info!("Health check");

    "OK"
}

async fn readyz(extract::State(state): extract::State<State>) -> impl IntoResponse {
    match state.get() {
        States::Starting => {
            info!("Ready check: Not ready (starting)");
            (StatusCode::SERVICE_UNAVAILABLE, "Starting")
        }
        States::Running => {
            info!("Ready check: Ready");
            (StatusCode::OK, "OK")
        }
        States::FaultyConfig => {
            info!("Ready check: Not ready (faulty configuration)");
            (StatusCode::INTERNAL_SERVER_ERROR, "Faulty configuration")
        }
    }
}

pub fn routes<S>(state: State) -> axum::Router<S> {
    axum::Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}
