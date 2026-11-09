use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

const MAX_TRACKED_KEYS: usize = 10_000;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
    max_requests: u32,
    window: Duration,
}

struct RateLimiterInner {
    buckets: HashMap<String, Window>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

struct Window {
    count: u32,
    start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self::with_clock(max_requests, window, Box::new(Instant::now))
    }

    pub fn with_clock(
        max_requests: u32,
        window: Duration,
        now: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                now,
            })),
            max_requests,
            window,
        }
    }

    /// Returns `true` when the request is allowed.
    pub fn check(&self, key: &str) -> bool {
        if self.max_requests == 0 {
            return true;
        }
        let mut inner = self.inner.lock().unwrap();
        let now = (inner.now)();
        // prune expired
        inner
            .buckets
            .retain(|_, w| now.duration_since(w.start) < self.window);
        if inner.buckets.len() >= MAX_TRACKED_KEYS && !inner.buckets.contains_key(key) {
            // defensive cap: drop oldest-ish by clearing (simple)
            inner.buckets.clear();
        }
        let window = inner.buckets.entry(key.to_string()).or_insert(Window {
            count: 0,
            start: now,
        });
        if now.duration_since(window.start) >= self.window {
            window.count = 0;
            window.start = now;
        }
        if window.count >= self.max_requests {
            return false;
        }
        window.count += 1;
        true
    }
}

pub async fn rate_limit_middleware(
    limiter: RateLimiter,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if !limiter.check(&ip) {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "Too many requests"})),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_limiter(max: u32, window_secs: u64) -> (RateLimiter, StdArc<AtomicU64>) {
        let counter = StdArc::new(AtomicU64::new(0));
        let c = counter.clone();
        let limiter = RateLimiter::with_clock(
            max,
            Duration::from_secs(window_secs),
            Box::new(move || Instant::now() + Duration::from_secs(c.load(Ordering::Relaxed))),
        );
        (limiter, counter)
    }

    #[test]
    fn allows_up_to_limit() {
        let (limiter, _) = make_limiter(3, 3600);
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
        assert!(limiter.check("ip1"));
        assert!(!limiter.check("ip1"));
    }

    #[test]
    fn separate_keys_independent() {
        let (limiter, _) = make_limiter(1, 3600);
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"));
        assert!(limiter.check("b"));
    }

    #[test]
    fn disabled_when_zero() {
        let (limiter, _) = make_limiter(0, 3600);
        for _ in 0..100 {
            assert!(limiter.check("ip"));
        }
    }

    #[test]
    fn window_reset() {
        let (limiter, counter) = make_limiter(1, 10);
        assert!(limiter.check("ip"));
        assert!(!limiter.check("ip"));
        counter.store(11, Ordering::Relaxed);
        assert!(limiter.check("ip"));
    }
}
