use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Debug,
    Error,
    Critical,
}

/// Initialize logging with given log level
pub fn init_logging(level: LogLevel) {
    use tracing_subscriber::filter::LevelFilter;

    let filter = match level {
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Critical => LevelFilter::ERROR,
    };

    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();
}

/// Severity a finished request is logged at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestSeverity {
    Info,
    Warn,
    Error,
    Debug,
}

/// Maps a response status onto the severity it is logged at.
///
/// Split out of [`request_logging_middleware`] so the policy can be asserted
/// directly rather than through a tracing subscriber.
fn request_severity(status: u16) -> RequestSeverity {
    match status {
        200..=299 => RequestSeverity::Info,
        400..=499 => RequestSeverity::Warn,
        500..=599 => RequestSeverity::Error,
        _ => RequestSeverity::Debug,
    }
}

/// Request logging middleware - logs all requests
///
/// NOTE: This middleware does NOT require ConnectInfo.
/// It logs: method, path, status code, and response time.
pub async fn request_logging_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    let start = Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    match request_severity(status.as_u16()) {
        RequestSeverity::Info => {
            tracing::info!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        RequestSeverity::Warn => {
            tracing::warn!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        RequestSeverity::Error => {
            tracing::error!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        RequestSeverity::Debug => {
            tracing::debug!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Info, LogLevel::Info);
        assert_eq!(LogLevel::Debug, LogLevel::Debug);
        assert_ne!(LogLevel::Info, LogLevel::Debug);
    }

    #[test]
    fn test_log_level_debug() {
        let level = LogLevel::Debug;
        assert_eq!(level, LogLevel::Debug);
    }

    #[test]
    fn successful_responses_are_logged_at_info() {
        assert_eq!(request_severity(200), RequestSeverity::Info);
        assert_eq!(request_severity(201), RequestSeverity::Info);
        assert_eq!(request_severity(299), RequestSeverity::Info);
    }

    #[test]
    fn client_errors_are_logged_at_warn() {
        assert_eq!(request_severity(400), RequestSeverity::Warn);
        assert_eq!(request_severity(404), RequestSeverity::Warn);
        assert_eq!(request_severity(499), RequestSeverity::Warn);
    }

    #[test]
    fn server_errors_are_logged_at_error() {
        assert_eq!(request_severity(500), RequestSeverity::Error);
        assert_eq!(request_severity(503), RequestSeverity::Error);
        assert_eq!(request_severity(599), RequestSeverity::Error);
    }

    #[test]
    fn everything_else_is_logged_at_debug() {
        assert_eq!(request_severity(100), RequestSeverity::Debug);
        assert_eq!(request_severity(199), RequestSeverity::Debug);
        assert_eq!(request_severity(300), RequestSeverity::Debug);
        assert_eq!(request_severity(399), RequestSeverity::Debug);
        assert_eq!(request_severity(600), RequestSeverity::Debug);
    }
}
