//! Error-response contract for the real handlers in `keyrunes::handler::errors`.
//!
//! The routes below mount the production handlers rather than copies of them:
//! a test that re-implements the code it is checking stays green when the code
//! it is meant to guard breaks.
//!
//! The error routes sit under `/api/` because `handler_404` negotiates its
//! body format, and an API client is the caller whose contract these tests
//! describe.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use keyrunes::handler::errors::{handler_400, handler_401, handler_403, handler_404};
use serde_json::Value;
use tower::ServiceExt;

/// A route that succeeds, so the fallback can be shown not to swallow it.
async fn ok_endpoint() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({ "status": "healthy" }))
}

/// Helper to create test application
async fn create_test_app() -> Router {
    Router::new()
        .route("/api/health", get(ok_endpoint))
        .route("/api/test/400", get(handler_400))
        .route("/api/test/401", get(handler_401))
        .route("/api/test/403", get(handler_403))
        .route("/api/test/404", get(handler_404))
        .fallback(handler_404)
}

/// Helper to verify error response structure
fn verify_error_structure(json: &Value, expected_code: u16) {
    assert!(json.get("error").is_some(), "Missing 'error' field");
    assert!(json.get("message").is_some(), "Missing 'message' field");
    assert!(
        json.get("status_code").is_some(),
        "Missing 'status_code' field"
    );

    assert!(json["error"].is_string(), "'error' should be string");
    assert!(json["message"].is_string(), "'message' should be string");
    assert!(
        json["status_code"].is_number(),
        "'status_code' should be number"
    );

    assert_eq!(
        json["status_code"], expected_code,
        "Expected status code {}, got {}",
        expected_code, json["status_code"]
    );
}

#[tokio::test]
async fn test_400_bad_request_returns_json() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/test/400")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Act
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    // Assert
    verify_error_structure(&json, 400);
    assert_eq!(json["error"], "Bad Request");
}

#[tokio::test]
async fn test_401_unauthorized_returns_json() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/test/401")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Act
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    // Assert
    verify_error_structure(&json, 401);
    assert_eq!(json["error"], "Unauthorized");
}

#[tokio::test]

async fn test_403_forbidden_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/test/403")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 403);
    assert_eq!(json["error"], "Forbidden");
}

#[tokio::test]

async fn test_404_not_found_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/test/404")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]

async fn test_all_error_codes_have_consistent_structure() {
    let app = create_test_app().await;

    let test_cases = vec![
        ("/api/test/400", StatusCode::BAD_REQUEST, 400),
        ("/api/test/401", StatusCode::UNAUTHORIZED, 401),
        ("/api/test/403", StatusCode::FORBIDDEN, 403),
        ("/api/test/404", StatusCode::NOT_FOUND, 404),
    ];

    for (path, expected_status, expected_code) in test_cases {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            expected_status,
            "Path {} should return {:?}",
            path,
            expected_status
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        verify_error_structure(&json, expected_code);
    }
}

#[tokio::test]
async fn test_fallback_404_on_invalid_route() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/completely/invalid/route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Act
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    // Assert
    verify_error_structure(&json, 404);
}

#[tokio::test]

async fn test_error_messages_are_descriptive() {
    let app = create_test_app().await;

    let test_cases = vec![
        ("/api/test/400", "Bad request"),
        ("/api/test/401", "Unauthorized"),
        ("/api/test/403", "Forbidden"),
        ("/api/test/404", "Not found"),
    ];

    for (path, expected_substring) in test_cases {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        let message = json["message"].as_str().expect("message should be string");
        assert!(
            message
                .to_lowercase()
                .contains(&expected_substring.to_lowercase()),
            "Message '{}' should contain '{}'",
            message,
            expected_substring
        );
    }
}

#[tokio::test]

async fn test_errors_dont_leak_sensitive_info() {
    let app = create_test_app().await;

    let paths = vec![
        "/api/test/400",
        "/api/test/401",
        "/api/test/403",
        "/api/test/404",
    ];

    for path in paths {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(!body_str.contains("src/"));
        assert!(!body_str.contains("Backtrace"));
        assert!(!body_str.contains("panic"));
        assert!(!body_str.contains("database"));
        assert!(!body_str.contains("password"));
        assert!(!body_str.contains("secret"));
    }
}

#[tokio::test]

async fn test_error_responses_with_different_http_methods() {
    let app = create_test_app().await;

    let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];

    for method in methods {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Method {} should return 404",
            method
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        verify_error_structure(&json, 404);
    }
}

#[tokio::test]

async fn test_valid_endpoint_still_works() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    assert_eq!(json["status"], "healthy");
}

#[tokio::test]

async fn test_error_content_type_is_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/test/404")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok());

    assert!(
        content_type.is_some(),
        "Content-Type header should be present"
    );
    assert!(
        content_type.unwrap().contains("application/json"),
        "Content-Type should be application/json"
    );
}
