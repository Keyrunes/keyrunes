//! Content negotiation for the real 404 handler in `keyrunes::handler::errors`.
//!
//! The fallback below is the production `handler_404`, not a copy of it: a
//! test that re-implements the code it is checking stays green when the code
//! it is meant to guard breaks.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use keyrunes::handler::errors::handler_404;
use tower::ServiceExt;

/// A route that succeeds, so the fallback can be shown not to swallow it.
async fn ok_endpoint() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({ "status": "healthy" }))
}

async fn create_test_app() -> Router {
    Router::new()
        .route("/api/health", get(ok_endpoint))
        .fallback(handler_404)
}

#[tokio::test]
async fn test_api_route_returns_json_404() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("application/json"),
        "API routes should return JSON"
    );

    // Act
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Assert
    assert_eq!(json["status_code"], 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]
async fn test_browser_route_returns_html_404() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("text/html"),
        "Browser requests should return HTML"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("404"));
    assert!(html.contains("<!DOCTYPE html>") || html.contains("<html>"));
}

#[tokio::test]
async fn test_json_accept_header_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status_code"], 404);
}

#[tokio::test]
async fn test_no_accept_header_returns_html() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();

    assert!(content.contains("<html>") || content.contains("<!DOCTYPE"));
}

#[tokio::test]
async fn test_api_prefix_always_json() {
    let app = create_test_app().await;

    let api_paths = vec![
        "/api/users",
        "/api/posts/123",
        "/api/v1/something",
        "/api/admin/users",
    ];

    for path in api_paths {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let json: Result<serde_json::Value, _> = serde_json::from_slice(&body);
        assert!(
            json.is_ok(),
            "API route {} should return JSON even with HTML accept header",
            path
        );
    }
}

#[tokio::test]
async fn test_valid_route_still_works() {
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
}

#[tokio::test]
async fn test_json_structure_is_correct() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("error").is_some());
    assert!(json.get("message").is_some());
    assert!(json.get("status_code").is_some());
    assert_eq!(json["status_code"], 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]
async fn test_html_page_has_useful_content() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/missing-page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("404"));
    assert!(html.to_lowercase().contains("not found") || html.to_lowercase().contains("page"));
}

#[tokio::test]

async fn test_mixed_accept_headers() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/page")
                .header("accept", "text/html, application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let json: Result<serde_json::Value, _> = serde_json::from_slice(&body);
    assert!(
        json.is_ok(),
        "Should return JSON when application/json is in Accept header"
    );
}
