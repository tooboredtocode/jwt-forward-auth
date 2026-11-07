use std::fmt;

/// Why an HTTP request failed before a response arrived, for errors whose cause `reqwest`
/// doesn't include in its message (it only prints "error sending request for url (...)").
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RequestErrorKind {
    /// The connection to the server could not be established.
    Connect,
    /// The request timed out. Takes precedence over `Connect`, since `reqwest` reports a
    /// connect timeout as both.
    Timeout,
}

impl RequestErrorKind {
    /// Classifies `err`, or returns `None` if it is neither a connect nor a timeout error.
    pub fn of(err: &reqwest::Error) -> Option<Self> {
        if err.is_timeout() {
            Some(Self::Timeout)
        } else if err.is_connect() {
            Some(Self::Connect)
        } else {
            None
        }
    }
}

impl fmt::Display for RequestErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
        })
    }
}
