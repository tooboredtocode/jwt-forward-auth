use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct AtomicInstant {
    inner: AtomicU64,
}

impl AtomicInstant {
    fn new(val: u64) -> Self {
        Self {
            inner: AtomicU64::new(val),
        }
    }

    pub fn empty() -> Self {
        Self::new(0)
    }

    pub fn now() -> Self {
        Self::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_micros() as u64,
        )
    }

    pub fn to_now(&self) {
        self.inner.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn to_system_time(&self) -> SystemTime {
        let micros = self.inner.load(std::sync::atomic::Ordering::Relaxed);
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .expect("Time went backwards")
    }

    pub fn duration_until(&self, later: SystemTime) -> Result<Duration, Duration> {
        let later = later
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_micros() as u64;

        let now = self.inner.load(std::sync::atomic::Ordering::Relaxed);
        if later < now {
            Err(Duration::from_micros(now - later))
        } else {
            Ok(Duration::from_micros(later - now))
        }
    }

    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, Duration> {
        let earlier = earlier
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_micros() as u64;

        let now = self.inner.load(std::sync::atomic::Ordering::Relaxed);
        if now < earlier {
            Err(Duration::from_micros(earlier - now))
        } else {
            Ok(Duration::from_micros(now - earlier))
        }
    }

    pub fn elapsed(&self) -> Result<Duration, Duration> {
        self.duration_until(SystemTime::now())
    }

    /// Adds the duration to the current instant.
    ///
    /// Note: This is operation can overflow.
    pub fn add(&self, duration: Duration) {
        self.inner.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Subtracts the duration from the current instant.
    ///
    /// Note: This is operation can underflow.
    pub fn sub(&self, duration: Duration) {
        self.inner.fetch_sub(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

impl Clone for AtomicInstant {
    fn clone(&self) -> Self {
        Self {
            inner: AtomicU64::new(self.inner.load(std::sync::atomic::Ordering::Acquire)),
        }
    }
}
