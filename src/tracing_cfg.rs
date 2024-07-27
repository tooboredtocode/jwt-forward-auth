use tracing::Level;
use tracing_subscriber::EnvFilter;

pub fn register_subscriber(use_ansi: bool, env_filter: &str) {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .parse_lossy(env_filter);

    tracing_subscriber::fmt()
        .with_ansi(use_ansi)
        .with_env_filter(filter)
        .init();
}
