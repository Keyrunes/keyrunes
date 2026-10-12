use axum::{
    extract::{Extension, Json, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::handler::errors::ErrorResponse;
use crate::repository::sqlx_impl::{
    PgGroupRepository, PgOrganizationRepository, PgPasswordResetRepository, PgSettingsRepository,
    PgUserRepository,
};
use crate::services::user_service::{
    AuthResponse, ChangePasswordRequest, ForgotPasswordRequest, RegisterRequest,
    ResetPasswordRequest, UserResponse, UserService,
};
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct RegisterApi {
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "username")]
    pub username: String,
    #[schema(example = "password123")]
    pub password: String,
    #[schema(example = "1")]
    #[serde(
        default,
        deserialize_with = "crate::api::deserializers::deserialize_option_string_or_number"
    )]
    pub organization_id: Option<i64>,
    #[schema(example = "tenant_namespace")]
    pub namespace: String,
    #[schema(example = "users")]
    pub group: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginApi {
    #[schema(example = "username_or_email")]
    pub identity: String,
    #[schema(example = "password123")]
    pub password: String,
    #[schema(example = "tenant_namespace")]
    pub namespace: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct RefreshTokenResponse {
    pub token: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ForgotPasswordApi {
    #[schema(example = "user@example.com")]
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "tenant_namespace")]
    pub namespace: String,
}

#[derive(Serialize, ToSchema)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordQuery {
    pub forgot_password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordApi {
    pub token: String,
    pub new_password: String,
    pub namespace: String,
}

#[derive(Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

type UserServiceType = UserService<
    PgUserRepository,
    PgGroupRepository,
    PgPasswordResetRepository,
    PgSettingsRepository,
    PgOrganizationRepository,
>;

/// POST /api/register
#[utoipa::path(
    post,
    path = "/api/register",
    request_body = RegisterApi,
    responses(
        (status = 201, description = "User registered successfully", body = AuthResponse),
        (status = 400, description = "Bad Request (e.g., email already exists)")
    ),
    tag = "auth"
)]
pub async fn register_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<RegisterApi>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        organization_id: payload.organization_id,
        email: payload.email,
        username: payload.username,
        password: payload.password,
        first_login: Some(true),
        group: payload.group,
    };

    match service.register(req, &payload.namespace).await {
        Ok(auth_response) => (StatusCode::CREATED, Json(auth_response.user)).into_response(),
        Err(e) => {
            tracing::error!("Registration failed: {:?}", e);
            ErrorResponse::bad_request(e.to_string()).into_response()
        }
    }
}

/// POST /api/login
#[utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginApi,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn login_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<LoginApi>,
) -> impl IntoResponse {
    match service
        .login(payload.identity, payload.password, &payload.namespace)
        .await
    {
        Ok(auth_response) => (StatusCode::OK, Json(auth_response)).into_response(),
        // SECURITY: log the internal error, but never echo database/backend
        // details (e.g. `relation "users" does not exist`) to the client.
        Err(e) => {
            tracing::warn!("login failed: {}", e);
            ErrorResponse::unauthorized("Invalid credentials".to_string()).into_response()
        }
    }
}

/// POST /api/refresh-token
#[utoipa::path(
    post,
    path = "/api/refresh-token",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed successfully", body = RefreshTokenResponse),
        (status = 401, description = "Invalid or expired token")
    ),
    tag = "auth"
)]
pub async fn refresh_token_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    match service.refresh_token(&payload.token).await {
        Ok(new_token) => (
            StatusCode::OK,
            Json(RefreshTokenResponse { token: new_token }),
        )
            .into_response(),
        Err(e) => ErrorResponse::unauthorized(e.to_string()).into_response(),
    }
}

/// GET /api/me - Get current user info from JWT token
#[utoipa::path(
    get,
    path = "/api/me",
    responses(
        (status = 200, description = "Current user info", body = UserResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "auth"
)]
pub async fn me_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    match service.get_user_by_token(&token).await {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(e) => ErrorResponse::unauthorized(e.to_string()).into_response(),
    }
}

/// POST /api/change-password
#[allow(dead_code)]
pub async fn change_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    headers: HeaderMap,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    let claims = match service.jwt_service.verify_token(&token) {
        Ok(claims) => claims,
        Err(e) => return ErrorResponse::unauthorized(e.to_string()).into_response(),
    };

    let user_id = match claims.sub.parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return ErrorResponse::unauthorized("Invalid user ID in token".to_string())
                .into_response();
        }
    };

    match service
        .change_password(user_id, payload, &claims.namespace)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password changed successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

/// POST /api/forgot-password
#[utoipa::path(
    post,
    path = "/api/forgot-password",
    request_body = ForgotPasswordApi,
    responses(
        (status = 200, description = "Request password reset", body = ForgotPasswordResponse),
        (status = 400, description = "Bad Request (e.g., email not found)")
    ),
    tag = "auth"
)]
pub async fn forgot_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<ForgotPasswordApi>,
) -> impl IntoResponse {
    let req = ForgotPasswordRequest {
        email: payload.email,
    };

    match service.forgot_password(req, &payload.namespace).await {
        Ok(_token) => {
            // SECURITY: the reset token is delivered exclusively by e-mail from
            // the service layer. Returning it in the HTTP response let any
            // anonymous caller reset an arbitrary account's password (account
            // takeover). Never put it back in the body.
            (
                StatusCode::OK,
                Json(ForgotPasswordResponse {
                    message: "If the email is registered, you will receive a reset link."
                        .to_string(),
                }),
            )
                .into_response()
        }
        // SECURITY: return the same generic response whether or not the e-mail
        // exists, so the endpoint cannot be used to enumerate users.
        Err(e) => {
            tracing::debug!("forgot-password lookup failed: {}", e);
            (
                StatusCode::OK,
                Json(ForgotPasswordResponse {
                    message: "If the email is registered, you will receive a reset link."
                        .to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /reset-password?forgot_password=TOKEN - Display reset password form
#[allow(dead_code)]
pub async fn reset_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    Query(params): Query<ResetPasswordQuery>,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "Reset Password");
    ctx.insert("token", &params.forgot_password);

    match tmpl.render("reset_password.html", &ctx) {
        Ok(body) => (StatusCode::OK, axum::response::Html(body)).into_response(),
        Err(e) => {
            ErrorResponse::internal_server_error(format!("Template error: {}", e)).into_response()
        }
    }
}

/// POST /api/reset-password
#[utoipa::path(
    post,
    path = "/api/reset-password",
    request_body = ResetPasswordApi,
    responses(
        (status = 200, description = "Reset password", body = MessageResponse),
        (status = 400, description = "Bad Request (e.g., invalid token)")
    ),
    tag = "auth"
)]
pub async fn reset_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<ResetPasswordApi>,
) -> impl IntoResponse {
    let req = ResetPasswordRequest {
        token: payload.token,
        new_password: payload.new_password,
    };

    match service.reset_password(req, &payload.namespace).await {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password reset successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_header) = headers.get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && auth_str.starts_with("Bearer ")
        && auth_str.len() > 7
    {
        return Some(auth_str[7..].to_string());
    }

    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some(token_value) = cookie.strip_prefix("jwt_token=")
                && !token_value.is_empty()
            {
                return Some(token_value.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=cookie_token; other=value"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("cookie_token".to_string()));
    }

    #[test]
    fn test_register_api_payload() {
        let payload = RegisterApi {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
            organization_id: None,
            namespace: "public".to_string(),
            group: None,
        };

        assert_eq!(payload.email, "test@example.com");
        assert_eq!(payload.username, "testuser");
    }

    /// SECURITY regression: the forgot-password response type must not carry
    /// the reset token. This test fails to compile if `reset_url` returns,
    /// and asserts the serialized body only contains the generic message.
    #[test]
    fn forgot_password_response_does_not_leak_token() {
        let resp = ForgotPasswordResponse {
            message: "If the email is registered, you will receive a reset link.".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();

        assert!(json.get("reset_url").is_none());
        assert!(json.get("token").is_none());
        assert_eq!(
            json.get("message").and_then(|m| m.as_str()),
            Some("If the email is registered, you will receive a reset link.")
        );
    }
}
