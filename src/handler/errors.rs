use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde::Serialize;

/// Standard error response structure
#[derive(Debug, Serialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub status_code: u16,
}

#[allow(dead_code)]
impl ErrorResponse {
    /// Create a new error response
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            error: status
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .to_string(),
            message: message.into(),
            status_code: status.as_u16(),
        }
    }

    /// Create a 400 Bad Request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Create a 401 Unauthorized error
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// Create a 403 Forbidden error
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// Create a 404 Not Found error
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// Create a 500 Internal Server Error
    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        (status, Json(self)).into_response()
    }
}

/// Check if request is from API (wants JSON) or browser (wants HTML)
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| accept.contains("application/json") || accept.contains("*/json"))
        .unwrap_or(false)
}

/// Check if the request path is an API route
fn is_api_route(path: &str) -> bool {
    path.starts_with("/api/")
}

/// Smart 404 handler - returns JSON for API routes, HTML for pages
pub async fn handler_404(req: Request) -> impl IntoResponse {
    let uri = req.uri().clone();
    let path = uri.path();
    let headers = req.headers().clone();

    if is_api_route(path) || wants_json(&headers) {
        return ErrorResponse::not_found("The requested resource was not found").into_response();
    }

    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        .error-code {
            font-size: 6rem;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 2rem;
            color: #2d3748;
            margin-bottom: 1rem;
        }
        p {
            font-size: 1.1rem;
            color: #718096;
            margin-bottom: 2rem;
            line-height: 1.6;
        }
        .links {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        a {
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #f7fafc;
            color: #4a5568;
            border: 2px solid #e2e8f0;
        }
        .btn-secondary:hover {
            background: #edf2f7;
            border-color: #cbd5e0;
        }
        .emoji {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="emoji">🔍</div>
        <div class="error-code">404</div>
        <h1>Page Not Found</h1>
        <p>
            Oops! The page you're looking for doesn't exist. 
            It might have been moved or deleted.
        </p>
        <div class="links">
            <a href="/" class="btn-primary">Go Home</a>
            <a href="/login" class="btn-secondary">Login</a>
        </div>
    </div>
</body>
</html>
    "#;

    (StatusCode::NOT_FOUND, Html(html)).into_response()
}

/// Handler for 400 Bad Request errors
#[allow(dead_code)]
pub async fn handler_400() -> impl IntoResponse {
    ErrorResponse::bad_request("Bad request")
}

/// Handler for 401 Unauthorized errors
#[allow(dead_code)]
pub async fn handler_401() -> impl IntoResponse {
    ErrorResponse::unauthorized("Unauthorized - Authentication required")
}

/// Handler for 403 Forbidden errors
#[allow(dead_code)]
pub async fn handler_403() -> impl IntoResponse {
    ErrorResponse::forbidden("Forbidden - Insufficient permissions")
}

/// Handler for 500 Internal Server Error
#[allow(dead_code)]
pub async fn handler_500() -> impl IntoResponse {
    ErrorResponse::internal_server_error("Internal server error occurred")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::Request as HttpRequest;
    use exhaustive::{Exhaustive, exhaustive_test};

    #[tokio::test]
    async fn test_error_handlers() {
        // Test 404 handler
        let req = HttpRequest::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();
        let response = handler_404(req).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = handler_400().await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = handler_401().await.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = handler_403().await.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = handler_500().await.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    #[tokio::test]
    async fn test_404_includes_path() {
        let req = HttpRequest::builder()
            .uri("/api/nonexistent")
            .body(Body::empty())
            .unwrap();
        let response = handler_404(req).await.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("not found") || body_str.contains("404"));
    }

    fn accept(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("accept", value.parse().unwrap());
        headers
    }

    #[test]
    fn a_json_accept_header_asks_for_json() {
        assert!(wants_json(&accept("application/json")));
        assert!(wants_json(&accept("application/json;q=0.9")));
        assert!(wants_json(&accept("text/html, application/json")));
    }

    #[test]
    fn a_vendor_json_accept_header_asks_for_json() {
        assert!(wants_json(&accept("application/vnd.api*/json")));
    }

    #[test]
    fn a_browser_accept_header_does_not_ask_for_json() {
        assert!(!wants_json(&accept("text/html,application/xhtml+xml")));
        assert!(!wants_json(&accept("*/*")));
    }

    #[test]
    fn a_missing_or_unreadable_accept_header_does_not_ask_for_json() {
        assert!(!wants_json(&HeaderMap::new()));

        let mut headers = HeaderMap::new();
        // Bytes that are not valid UTF-8 must not be mistaken for a JSON request.
        headers.insert("accept", HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        assert!(!wants_json(&headers));
    }

    #[test]
    fn only_the_api_prefix_counts_as_an_api_route() {
        assert!(is_api_route("/api/users"));
        assert!(is_api_route("/api/"));

        assert!(!is_api_route("/api"));
        assert!(!is_api_route("/"));
        assert!(!is_api_route("/login"));
        assert!(!is_api_route("/docs/api/users"));
    }

    #[tokio::test]
    async fn an_unknown_api_route_answers_json() {
        let req = HttpRequest::builder()
            .uri("/api/nope")
            .body(Body::empty())
            .unwrap();
        let response = handler_404(req).await.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.contains("application/json"),
            "expected JSON, got {content_type}"
        );
    }

    #[tokio::test]
    async fn an_unknown_page_answers_html_to_a_browser() {
        let req = HttpRequest::builder()
            .uri("/nope")
            .header("accept", "text/html")
            .body(Body::empty())
            .unwrap();
        let response = handler_404(req).await.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.contains("text/html"),
            "expected HTML, got {content_type}"
        );
    }

    #[tokio::test]
    async fn an_unknown_page_answers_json_when_the_client_asks_for_it() {
        let req = HttpRequest::builder()
            .uri("/nope")
            .header("accept", "application/json")
            .body(Body::empty())
            .unwrap();
        let response = handler_404(req).await.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.contains("application/json"),
            "expected JSON, got {content_type}"
        );
    }

    // ---------------------------------------------------------------------
    // Exhaustive content negotiation for the 404 handler.
    //
    // Whether a miss answers JSON or HTML is decided by two independent
    // inputs, so the cross product of their interesting shapes is enumerated
    // rather than sampled. An API client that receives an HTML error page
    // fails to parse it; a browser that receives JSON shows raw text.
    // ---------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum PathShape {
        /// `/api/` — the boundary of the prefix itself.
        ApiPrefix,
        /// A real API path.
        ApiNested,
        /// `/api` with no trailing slash: outside the API surface.
        ApiNoSlash,
        /// `/apidocs` — starts with "/api" but is not under "/api/".
        ApiLookalike,
        /// `/api` appearing further down the path, not as the prefix.
        ApiInTheMiddle,
        /// A browser page.
        Page,
        /// The site root.
        Root,
    }

    impl PathShape {
        fn path(self) -> &'static str {
            match self {
                PathShape::ApiPrefix => "/api/",
                PathShape::ApiNested => "/api/users/42",
                PathShape::ApiNoSlash => "/api",
                PathShape::ApiLookalike => "/apidocs",
                PathShape::ApiInTheMiddle => "/docs/api/reference",
                PathShape::Page => "/login",
                PathShape::Root => "/",
            }
        }

        /// Only paths genuinely under `/api/` are API routes.
        fn is_api(self) -> bool {
            matches!(self, PathShape::ApiPrefix | PathShape::ApiNested)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum AcceptShape {
        /// No Accept header at all.
        Absent,
        Json,
        /// A browser-style list that happens to include JSON.
        JsonAmongOthers,
        /// The `*/json` form the implementation also honours.
        StarJson,
        Html,
        /// `*/*` — accepts anything, but names no JSON.
        StarStar,
        Empty,
        Garbage,
        /// Bytes that are not valid UTF-8, so `to_str()` fails.
        NonUtf8,
    }

    impl AcceptShape {
        fn header(self) -> Option<HeaderValue> {
            match self {
                AcceptShape::Absent => None,
                AcceptShape::Json => Some(HeaderValue::from_static("application/json")),
                AcceptShape::JsonAmongOthers => Some(HeaderValue::from_static(
                    "text/html,application/xhtml+xml,application/json;q=0.9",
                )),
                AcceptShape::StarJson => Some(HeaderValue::from_static("*/json")),
                AcceptShape::Html => Some(HeaderValue::from_static("text/html")),
                AcceptShape::StarStar => Some(HeaderValue::from_static("*/*")),
                AcceptShape::Empty => Some(HeaderValue::from_static("")),
                AcceptShape::Garbage => Some(HeaderValue::from_static(";;;not-a-media-type;;;")),
                AcceptShape::NonUtf8 => Some(HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap()),
            }
        }

        /// Only a header that actually names JSON asks for JSON.
        fn asks_for_json(self) -> bool {
            matches!(
                self,
                AcceptShape::Json | AcceptShape::JsonAmongOthers | AcceptShape::StarJson
            )
        }
    }

    /// All 7 x 9 = 63 combinations of path shape and Accept header. The body
    /// format must follow "API route or client asked for JSON", and the status
    /// must be 404 in every single case.
    #[exhaustive_test]
    fn the_404_body_format_follows_route_and_accept(path: PathShape, accept: AcceptShape) {
        let mut builder = HttpRequest::builder().uri(path.path());
        if let Some(value) = accept.header() {
            builder = builder.header("accept", value);
        }
        let req = builder.body(Body::empty()).unwrap();

        let response = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build a test runtime")
            .block_on(async { handler_404(req).await.into_response() });

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a miss must be 404 whatever the client asked for: {path:?} {accept:?}"
        );

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let served_json = content_type.contains("application/json");

        assert_eq!(
            served_json,
            path.is_api() || accept.asks_for_json(),
            "wrong body format for {path:?} with {accept:?} (content-type {content_type})"
        );
    }

    /// `is_api_route` and `wants_json` are the two halves of that decision;
    /// pin each one on its own so a failure above says which half moved.
    #[exhaustive_test]
    fn is_api_route_recognises_only_the_api_prefix(path: PathShape) {
        assert_eq!(is_api_route(path.path()), path.is_api(), "{path:?}");
    }

    #[exhaustive_test]
    fn wants_json_reads_only_the_accept_header(accept: AcceptShape) {
        let mut headers = HeaderMap::new();
        if let Some(value) = accept.header() {
            headers.insert("accept", value);
        }
        assert_eq!(wants_json(&headers), accept.asks_for_json(), "{accept:?}");
    }
}
