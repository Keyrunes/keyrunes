use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
};
use keyrunes::api;
use keyrunes::handler::errors::handler_404;
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
use tera::Tera;
use tower::ServiceExt;
use url::Url;

async fn create_test_app() -> Router {
    dotenvy::dotenv().ok();

    let database_url = if let Ok(url) = std::env::var("TEST_DATABASE_URL") {
        url
    } else if let Ok(url_str) = std::env::var("DATABASE_URL") {
        if let Ok(mut url) = Url::parse(&url_str) {
            url.set_path("keyrunes");
            url.to_string()
        } else {
            "postgres://postgres_user:pass123@localhost:5432/keyrunes".to_string()
        }
    } else {
        "postgres://postgres:password@localhost:5432/keyrunes".to_string()
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));
    let _org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let jwt_service = Arc::new(JwtService::new("test_secret"));
    let settings_repo = Arc::new(PgSettingsRepository::new(pool.clone()));
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        Arc::new(PgOrganizationRepository::new(pool.clone())),
        password_reset_repo,
        jwt_service.clone(),
        settings_service.clone(),
        None,
    ));

    let mut tera = Tera::new();
    tera.load_from_glob("templates/**/*")
        .expect("Error loading templates");

    Router::new()
        .route("/api/health", get(api::health::health_check))
        .route("/api/register", post(api::auth::register_api))
        .route("/api/login", post(api::auth::login_api))
        .fallback(handler_404)
        .layer(Extension(tera))
        .layer(Extension(user_service))
        .layer(Extension(jwt_service))
        .layer(Extension(pool))
}

#[tokio::test]
async fn test_health_check() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_404_handler() {
    // Setup
    let app = create_test_app().await;

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
