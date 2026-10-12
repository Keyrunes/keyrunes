use std::sync::Arc;

use axum::middleware::from_fn;
use axum::routing::{delete, get, patch, post};
use axum::{Router, extract::Extension, response::Redirect};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tera::Tera;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

use keyrunes::api;
use keyrunes::constants::MIN_JWT_SECRET_LENGTH;
use keyrunes::repository;
use keyrunes::services;
use keyrunes::views;

use keyrunes::handler::auth::{require_auth, require_org_key_or_superadmin, require_superadmin};
use keyrunes::handler::errors::handler_404;
use keyrunes::handler::logging::{
    LogLevel, init_logging, request_logging_middleware, security_headers_middleware,
};

use keyrunes::repository::sqlx_impl::PgOrganizationRepository;
use keyrunes::repository::sqlx_impl::PgSettingsRepository;
use keyrunes::services::organization_service::OrganizationService;
use keyrunes::services::user_service::SettingsService;
use repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgPolicyRepository, PgUserRepository,
};
use services::{
    email_service::EmailService, group_service::GroupService, jwt_service::JwtService,
    policy_service::PolicyService, user_service::UserService,
};

use crate::api::openapi::ApiDoc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Router for the OpenAPI spec and Swagger UI.
///
/// SECURITY: exposed only in debug builds. In release it is replaced by an
/// empty router so the full API surface (including admin routes) is not handed
/// to anonymous reconnaissance.
fn swagger_router() -> axum::Router {
    #[cfg(debug_assertions)]
    {
        SwaggerUi::new("/swagger-ui")
            .url("/api-docs/openapi.json", ApiDoc::openapi())
            .into()
    }
    #[cfg(not(debug_assertions))]
    {
        axum::Router::new()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let log_level_str = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let log_level = match log_level_str.to_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "error" => LogLevel::Error,
        "critical" => LogLevel::Critical,
        _ => LogLevel::Info,
    };

    init_logging(log_level);

    tracing::info!("🚀 Starting Keyrunes...");
    tracing::info!("📊 Log level configurated: {:?}", log_level);

    api::health::init_health_check();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/keyrunes".into());

    let conn_options = database_url
        .parse::<PgConnectOptions>()?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(conn_options)
        .await?;
    tracing::info!("✅ Database established!");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate database");
    tracing::info!("✅ Migrations completed!");

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));
    let organization_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));

    // SECURITY: never fall back to a hardcoded secret. A default secret allows
    // anyone to forge a superadmin JWT and take over every tenant (auth bypass,
    // CVSS 9.8). Refuse to start without an explicit, sufficiently long secret.
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        panic!(
            "JWT_SECRET environment variable is required and must be at least {} bytes. \
             Generate one with: openssl rand -base64 48",
            MIN_JWT_SECRET_LENGTH
        )
    });
    if jwt_secret.len() < MIN_JWT_SECRET_LENGTH {
        panic!(
            "JWT_SECRET must be at least {} bytes long (got {}); refusing to start with a weak secret.",
            MIN_JWT_SECRET_LENGTH,
            jwt_secret.len()
        );
    }
    let jwt_service = Arc::new(JwtService::new(&jwt_secret));
    let settings_repo = Arc::new(PgSettingsRepository::new(pool.clone()));
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let tera = Tera::new("templates/**/*").expect("Error to load templates");
    tracing::info!("✅ Templates loaded with success");

    let email_service = match EmailService::from_env(tera.clone().into()) {
        Ok(service) => {
            tracing::info!("✅ Email service configured");
            Some(Arc::new(service))
        }
        Err(e) => {
            tracing::warn!(
                "⚠️  Email service not configured: {}. Password reset tokens will be generated but emails won't be sent.",
                e
            );
            None
        }
    };

    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo.clone(),
        organization_repo.clone(),
        password_reset_repo,
        jwt_service.clone(),
        settings_service,
        email_service,
    ));
    let organization_service = Arc::new(OrganizationService::new(
        organization_repo,
        group_repo.clone(),
    ));

    let policy_repo = Arc::new(PgPolicyRepository::new(pool.clone()));
    let group_service = Arc::new(GroupService::new(group_repo));
    let policy_service = Arc::new(PolicyService::new(policy_repo));

    let public_router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/login") }))
        .route("/api/health", get(api::health::health_check))
        .route("/api/health/ready", get(api::health::readiness_check))
        .route("/api/health/live", get(api::health::liveness_check))
        .route(
            "/register",
            get(views::auth::register_page).post(views::auth::register_post),
        )
        .route("/api/register", post(api::auth::register_api))
        .route("/api/login", post(api::auth::login_api))
        .route(
            "/login",
            get(views::auth::login_page).post(views::auth::login_post),
        )
        .route("/forgot-password", get(views::auth::forgot_password_page))
        .route("/api/forgot-password", post(api::auth::forgot_password_api))
        .route("/reset-password", get(views::auth::reset_password_page))
        .route("/api/reset-password", post(api::auth::reset_password_api))
        .nest_service("/static", ServeDir::new("./static"));

    let protected_web_router = Router::new()
        .route("/dashboard", get(views::auth::dashboard_page))
        .route(
            "/change-password",
            get(views::auth::change_password_page).post(views::auth::change_password_post),
        )
        .route(
            "/profile",
            get(views::auth::profile_page).post(views::auth::profile_post),
        );

    let protected_api_router = Router::new()
        .route(
            "/api/admin/organizations",
            get(api::organization::list_organizations),
        )
        .route("/api/refresh-token", post(api::auth::refresh_token_api))
        .route("/api/me", get(api::auth::me_api))
        .route("/api/user/profile", patch(api::user::update_profile))
        .route(
            "/api/user/change-password",
            post(api::user::change_password),
        )
        .route("/api/org/secret", get(api::organization::get_org_key))
        .route(
            "/api/org/secret/rotate",
            post(api::organization::rotate_org_key),
        )
        .layer(from_fn(require_auth));

    let admin_web_router = Router::new()
        .route("/admin", get(views::admin::admin_page))
        .layer(from_fn(require_superadmin))
        .layer(from_fn(require_auth));

    let admin_router = Router::new()
        .route("/api/admin/dashboard", get(api::admin::admin_dashboard))
        .route("/api/admin/users", get(api::admin::list_users))
        .route(
            "/api/admin/users/{user_id}",
            delete(api::admin::delete_user).patch(api::admin::update_user),
        )
        .route(
            "/api/admin/users/{user_id}/reset-password",
            post(api::admin::admin_reset_user_password),
        )
        .route(
            "/api/admin/users/{user_id}/send-reset",
            post(api::admin::send_password_reset_email),
        )
        .route("/api/admin/user", post(api::admin::create_user))
        .route(
            "/api/admin/groups",
            get(api::admin::list_groups).post(api::admin::create_group),
        )
        .route(
            "/api/admin/policies",
            get(api::admin::list_policies).post(api::admin::create_policy),
        )
        .route(
            "/api/admin/users/{user_id}/groups/{group_id}",
            post(api::admin::assign_user_to_group).delete(api::admin::remove_user_from_group),
        )
        .route(
            "/api/admin/check-permission",
            post(api::admin::check_permission),
        )
        .route(
            "/api/admin/organizations",
            post(api::organization::create_organization),
        )
        .route(
            "/api/admin/organizations/{id}",
            delete(api::organization::delete_organization),
        )
        .route(
            "/api/admin/organizations/{id}/rotate-key",
            post(api::organization::admin_rotate_org_key),
        )
        .layer(from_fn(require_superadmin))
        .layer(from_fn(require_auth));

    let external_api_router = Router::new()
        .route(
            "/api/verify-org-key",
            get(
                |Extension(org): Extension<keyrunes::repository::Organization>| async move {
                    axum::Json(serde_json::json!({
                        "status": "success",
                        "organization": org.name,
                        "organization_id": org.organization_id
                    }))
                },
            ),
        )
        .route(
            "/api/check-permission",
            post(api::external::check_permission),
        )
        .layer(from_fn(require_org_key_or_superadmin));

    let app = Router::new()
        .merge(public_router)
        .merge(protected_web_router)
        .merge(protected_api_router)
        .merge(admin_web_router)
        .merge(admin_router)
        .merge(external_api_router)
        .merge(swagger_router())
        .fallback(handler_404)
        .layer(Extension(tera))
        .layer(Extension(user_service))
        .layer(Extension(group_service))
        .layer(Extension(policy_service))
        .layer(Extension(organization_service))
        .layer(Extension(jwt_service))
        .layer(Extension(pool))
        .layer(from_fn(request_logging_middleware))
        .layer(from_fn(security_headers_middleware));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    tracing::info!("🛡️ KeyRunes server starting on http://{}", addr);
    tracing::info!("📚 Available endpoints:");
    tracing::info!("  • Swagger UI: /swagger-ui/");
    tracing::info!("  • Health: /api/health, /api/health/ready, /api/health/live");
    tracing::info!("  • Public: /login, /register, /forgot-password, /reset-password");
    tracing::info!("  • Protected: /dashboard, /change-password");
    tracing::info!(
        "  • API: /api/login, /api/register, /api/forgot-password, /api/reset-password, /api/me, /api/refresh-token"
    );
    tracing::info!("  • Admin Web (superadmin only):");
    tracing::info!("    - Admin Panel: GET /admin");
    tracing::info!("  • Admin API (superadmin only):");
    tracing::info!("    - Dashboard: GET /api/admin/dashboard");
    tracing::info!("    - Users: GET /api/admin/users, POST /api/admin/user");
    tracing::info!("    - Groups: GET/POST /api/admin/groups");
    tracing::info!("    - Policies: GET/POST /api/admin/policies");
    tracing::info!(
        "    - User-Group: POST/DELETE /api/admin/users/{{user_id}}/groups/{{group_id}}"
    );
    tracing::info!("    - Check Permission: POST /api/admin/check-permission");

    axum::serve(listener, app).await.unwrap();

    Ok(())
}
