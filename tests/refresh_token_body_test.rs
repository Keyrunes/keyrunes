use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use keyrunes::api;
use keyrunes::handler::auth::AuthenticatedUser;
use keyrunes::repository::sqlx_impl::{
    PgGroupRepository, PgOrganizationRepository, PgPasswordResetRepository, PgSettingsRepository,
    PgUserRepository,
};
use keyrunes::services::{
    jwt_service::JwtService,
    user_service::{SettingsService, UserService},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

/// The identity injected into the handler extensions.
fn session_user() -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: 1,
        email: "refresh-user@test.local".to_string(),
        username: "refresh-user".to_string(),
        groups: vec!["users".to_string()],
        namespace: "public".to_string(),
        organization_id: 1,
    }
}

/// Build a router around the real refresh handler.
///
/// The pool is lazy on purpose: the test asserts that the request body is
/// never deserialized, so the outcome must be the same with a JSON object, a
/// malformed body or no body at all — never a 422 from the JSON extractor.
async fn test_app() -> Router {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:password@localhost:5432/keyrunes")
        .expect("lazy pool");

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));
    let organization_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let settings_repo = Arc::new(PgSettingsRepository::new(pool.clone()));

    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        organization_repo,
        password_reset_repo,
        Arc::new(JwtService::new("test_secret")),
        Arc::new(SettingsService::new(settings_repo)),
        None,
    ));

    Router::new()
        .route("/api/refresh-token", post(api::auth::refresh_token_api))
        .layer(Extension(user_service))
        .layer(Extension(session_user()))
}

async fn refresh_status(app: &Router, body: Option<&str>) -> StatusCode {
    let builder = Request::builder()
        .method("POST")
        .uri("/api/refresh-token")
        .header("Content-Type", "application/json");

    let request = match body {
        Some(payload) => builder.body(Body::from(payload.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    app.clone().oneshot(request).await.unwrap().status()
}

/// The body of `POST /api/refresh-token` must be ignored: the refreshed token
/// is always minted for the identity of the verified Bearer token, so the
/// server has no reason to parse (or even accept) a payload.
#[tokio::test]
async fn refresh_ignores_the_request_body() {
    let app = test_app().await;

    let without_body = refresh_status(&app, None).await;
    let with_empty_object = refresh_status(&app, Some("{}")).await;
    let with_legacy_token = refresh_status(&app, Some(r#"{"token":"stale"}"#)).await;
    let with_garbage = refresh_status(&app, Some("not-json-at-all")).await;

    for (label, status) in [
        ("empty JSON object", with_empty_object),
        ("legacy token payload", with_legacy_token),
        ("malformed body", with_garbage),
    ] {
        assert_ne!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "the body must not be deserialized ({label} answered 422)"
        );
        assert_eq!(
            status, without_body,
            "the body must be ignored: {label} answered {status}, expected {without_body}"
        );
    }
}
