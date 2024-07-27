use crate::utils::Shutdown;
use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use axum::{Router, ServiceExt};
use std::time::Duration;
use this_state::State as ThisState;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, Span};

mod args;
mod probes;
mod tracing_cfg;
mod utils;
mod validator_file;
mod validators;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum States {
    /// The application is starting up.
    Starting,
    /// The application is running normally.
    Running,
    /// The application currently only has a faulty configuration available.
    FaultyConfig,
}

pub type State = ThisState<States>;

fn main() {
    let args = args::Args::parse();

    tracing_cfg::register_subscriber(args.ansi, &args.log);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            error!("Failed to create runtime: {}", err);
            return;
        }
    };

    let _ = runtime.block_on(async_main(args));

    info!("Main loop finished, waiting for remaining tasks to finish");
    runtime.shutdown_timeout(Duration::from_secs(30));
    info!("Runtime shutdown complete");
}

async fn async_main(args: args::Args) -> Result<(), Shutdown> {
    info!("Starting up");

    let state = State::new(States::Starting);
    let validators = validators::Store::new(state.clone(), reqwest::Client::new());
    validators.start_file_watcher(args.config).await?;

    let app = Router::new()
        .merge(probes::routes(state.clone()))
        .nest("/auth", validators::routes(validators.state()))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!(
                        "http-request",
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                        status_code = tracing::field::Empty,
                    )
                })
                .on_request(|_: &Request<_>, _: &Span| {
                    debug!("Received request");
                })
                .on_response(|res: &Response<_>, _: Duration, span: &Span| {
                    span.record(
                        "status_code",
                        &tracing::field::display(res.status().as_u16()),
                    );

                    debug!("Finished processing request");
                })
                // We don't care about the following events
                // - on_failure: we manually handle errors
                .on_failure(|_: ServerErrorsFailureClass, _: Duration, _: &Span| {})
                .on_body_chunk(|_: &Bytes, _: Duration, _: &Span| {})
                .on_eos(|_: Option<&HeaderMap>, _: Duration, _: &Span| {}),
        )
        .layer(NormalizePathLayer::trim_trailing_slash());

    let listener = tokio::net::TcpListener::bind(args.listen_address).await?;
    axum::serve(listener, ServiceExt::<Request>::into_make_service(app)).await?;

    Ok(())
}
