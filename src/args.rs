use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
pub struct Args {
    /// The address and port to bind to.
    #[clap(
        long = "listen",
        default_value = "0.0.0.0:8080",
        env = "LISTEN_ADDRESS"
    )]
    pub listen_address: SocketAddr,

    /// The path to the configuration file (which is dynamically reloaded).
    #[clap(short, long, default_value = "config.yaml", env = "CONFIG")]
    pub config: PathBuf,

    /// The log filter configuration (e.g. "info,my_crate=debug").
    #[clap(short, long, default_value = "info", env = "JWT_FWA_LOG")]
    pub log: String,
    /// The log format configuration
    #[clap(
        short = 'f',
        long,
        default_value = "logfmt",
        env = "JWT_FWA_LOG_FORMAT"
    )]
    pub log_format: LogFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum LogFormat {
    /// Logfmt with ANSI color codes.
    Logfmt,
    /// Logfmt without ANSI color codes.
    LogfmtPlain,
    /// JSON.
    Json,
}

impl Args {
    pub fn parse() -> Self {
        Parser::parse()
    }
}
