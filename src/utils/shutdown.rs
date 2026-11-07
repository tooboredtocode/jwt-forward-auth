use std::fmt;
use tracing::error;

pub trait ShutdownContext<T> {
    fn with_context<F, C>(self, context: F) -> Result<T, Shutdown>
    where
        F: FnOnce() -> C,
        C: fmt::Display;
}

#[derive(Debug, Copy, Clone)]
pub struct Shutdown;

impl fmt::Display for Shutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shutdown")
    }
}

impl<E> From<E> for Shutdown
where
    E: std::error::Error,
{
    fn from(e: E) -> Self {
        error!(error = %e, "Fatal error, shutting down");

        Shutdown
    }
}

impl<T, E> ShutdownContext<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn with_context<F, C>(self, context: F) -> Result<T, Shutdown>
    where
        F: FnOnce() -> C,
        C: fmt::Display,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => {
                error!(error = %e, context = %context(), "Fatal error, shutting down");

                Err(Shutdown)
            }
        }
    }
}
