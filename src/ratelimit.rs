//! Token-bucket bandwidth limiter.

use std::time::Duration;

use tokio::time::Instant;

pub struct TokenBucket {
    /// Bytes per second; 0 means unlimited.
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// Allows `bytes_per_sec` sustained, with bursts of up to one second's worth.
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            rate: bytes_per_sec as f64,
            tokens: bytes_per_sec as f64,
            last: Instant::now(),
        }
    }

    pub fn from_mbps(mbps: u64) -> Self {
        Self::new(mbps * 1_000_000 / 8)
    }

    /// Waits until `bytes` may be sent.
    pub async fn take(&mut self, bytes: usize) {
        if self.rate == 0.0 {
            return;
        }
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.rate);
        self.last = now;
        self.tokens -= bytes as f64;
        if self.tokens < 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(-self.tokens / self.rate)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn throttles_to_rate() {
        let mut bucket = TokenBucket::new(1000);
        let start = tokio::time::Instant::now();
        // First second's worth is the burst; the next 2000 bytes take ~2 s.
        for _ in 0..30 {
            bucket.take(100).await;
        }
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(1900) && elapsed <= Duration::from_millis(2100), "{elapsed:?}");
    }

    #[tokio::test]
    async fn zero_is_unlimited() {
        let mut bucket = TokenBucket::new(0);
        bucket.take(usize::MAX / 2).await;
    }
}
