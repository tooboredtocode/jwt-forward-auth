use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Parser};

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

    /// Whether to output the log using ansi colors. [env: JWT_FWA_PLAIN_LOG=] [default: true]
    #[clap(short, long, action = ArgAction::SetFalse)]
    pub ansi: bool,
}

impl Args {
    pub fn parse() -> Self {
        let mut res: Self = Parser::parse();

        let plain = env::var_os("JWT_FWA_PLAIN_LOG");
        match plain.as_ref().map(|v| v.as_encoded_bytes()) {
            None | Some(b"0") | Some(b"f") | Some(b"false") => {}
            _ => res.ansi = false,
        }

        res
    }
}
