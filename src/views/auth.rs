use crate::handler::auth::extract_bearer_token;
use crate::repository::sqlx_impl::{
    PgGroupRepository, PgOrganizationRepository, PgPasswordResetRepository, PgSettingsRepository,
    PgUserRepository,
};
use crate::services::user_service::{
    ChangePasswordRequest, RegisterRequest, UpdateProfileRequest, UserService,
};
use axum::{
    extract::{Extension, Form, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::sync::Arc;
use tera::Context;

type UserServiceType = UserService<
    PgUserRepository,
    PgGroupRepository,
    PgPasswordResetRepository,
    PgSettingsRepository,
    PgOrganizationRepository,
>;

#[derive(serde::Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_login: bool,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

fn default_namespace() -> String {
    "public".to_string()
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub identity: String,
    pub password: String,
    pub namespace: String,
}

#[derive(serde::Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    pub forgot_password: String,
}

/// GET /register
pub async fn register_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Register");
    let body = tmpl.render("register.html", &ctx).unwrap();
    Html(body)
}

/// POST /register
pub async fn register_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<RegisterForm>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        organization_id: None,
        email: payload.email,
        username: payload.username,
        password: payload.password,
        first_login: Some(payload.first_login),
        group: None,
    };

    match service.register(req, &payload.namespace).await {
        Ok(auth_response) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Registration Successful");
            ctx.insert("user", &auth_response.user);
            ctx.insert("token", &auth_response.token);

            let cookie_value = format!(
                "jwt_token={}; Path=/; HttpOnly; SameSite=Strict",
                auth_response.token
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&cookie_value).unwrap(),
            );

            if auth_response.requires_password_change {
                return (
                    StatusCode::SEE_OTHER,
                    headers,
                    Redirect::to("/change-password"),
                )
                    .into_response();
            }
            (StatusCode::SEE_OTHER, headers, Redirect::to("/dashboard")).into_response()
        }
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Register");
            ctx.insert("error", &format!("{e}"));
            let body = tmpl.render("register.html", &ctx).unwrap();
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

/// GET /login
pub async fn login_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Login");
    let body = tmpl.render("login.html", &ctx).unwrap();
    Html(body)
}

/// POST /login
pub async fn login_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<LoginForm>,
) -> impl IntoResponse {
    match service
        .login(payload.identity, payload.password, &payload.namespace)
        .await
    {
        Ok(auth_response) => {
            let cookie_value = format!(
                "jwt_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600",
                auth_response.token
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&cookie_value).unwrap(),
            );

            if auth_response.requires_password_change {
                return (
                    StatusCode::SEE_OTHER,
                    headers,
                    Redirect::to("/change-password"),
                )
                    .into_response();
            }

            (StatusCode::SEE_OTHER, headers, Redirect::to("/dashboard")).into_response()
        }
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Login");
            ctx.insert("error", &format!("{e}"));
            let body = tmpl.render("login.html", &ctx).unwrap();
            (StatusCode::UNAUTHORIZED, Html(body)).into_response()
        }
    }
}

/// GET /change-password
pub async fn change_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Change Password");

    if let Some(token) = extract_bearer_token(&headers) {
        ctx.insert("token", &token);
    }

    let body = tmpl.render("change_password.html", &ctx).unwrap();
    Html(body)
}

/// POST /change-password
pub async fn change_password_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
    Form(payload): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return Redirect::to("/login").into_response();
        }
    };

    let claims = match service.jwt_service.verify_token(&token) {
        Ok(claims) => claims,
        Err(_) => {
            return Redirect::to("/login").into_response();
        }
    };

    let user_id = match claims.sub.parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return Redirect::to("/login").into_response();
        }
    };

    if payload.new_password != payload.confirm_password {
        let mut ctx = Context::new();
        ctx.insert("title", "Change Password");
        ctx.insert("error", "New passwords do not match");
        let body = tmpl.render("change_password.html", &ctx).unwrap();
        return (StatusCode::BAD_REQUEST, Html(body)).into_response();
    }

    let req = ChangePasswordRequest {
        current_password: payload.current_password,
        new_password: payload.new_password,
    };

    match service
        .change_password(user_id, req, &claims.namespace)
        .await
    {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Change Password");
            ctx.insert("error", &format!("{e}"));
            let body = tmpl.render("change_password.html", &ctx).unwrap();
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

/// GET /dashboard
pub async fn dashboard_page(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return Redirect::to("/login").into_response();
        }
    };

    match service.get_user_by_token(&token).await {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Dashboard");
            ctx.insert("user", &user);
            let body = tmpl.render("dashboard.html", &ctx).unwrap();
            Html(body).into_response()
        }
        Err(_) => Redirect::to("/login").into_response(),
    }
}

/// GET /forgot-password
pub async fn forgot_password_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Forgot Password");

    match tmpl.render("forgot_password.html", &ctx) {
        Ok(body) => Html(body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

/// GET /profile
pub async fn profile_page(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => return Redirect::to("/login").into_response(),
    };

    match service.get_user_by_token(&token).await {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Edit Profile");
            ctx.insert("user", &user);
            match tmpl.render("profile.html", &ctx) {
                Ok(body) => Html(body).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Template error: {}", e),
                )
                    .into_response(),
            }
        }
        Err(_) => Redirect::to("/login").into_response(),
    }
}

#[derive(Deserialize)]
pub struct ProfileForm {
    pub username: String,
    pub email: String,
}

/// POST /profile
pub async fn profile_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
    Form(payload): Form<ProfileForm>,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => return Redirect::to("/login").into_response(),
    };

    let claims = match service.jwt_service.verify_token(&token) {
        Ok(claims) => claims,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let user_id = match claims.sub.parse::<i64>() {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let update_req = UpdateProfileRequest {
        username: Some(payload.username),
        email: Some(payload.email),
    };

    match service
        .update_profile(user_id, update_req, &claims.namespace)
        .await
    {
        Ok(_) => match service.get_user_by_token(&token).await {
            Ok(user) => {
                let mut ctx = Context::new();
                ctx.insert("title", "Edit Profile");
                ctx.insert("user", &user);
                ctx.insert("success", "Profile updated successfully");
                let body = tmpl.render("profile.html", &ctx).unwrap();
                Html(body).into_response()
            }
            Err(_) => Redirect::to("/login").into_response(),
        },
        Err(e) => match service.get_user_by_token(&token).await {
            Ok(user) => {
                let mut ctx = Context::new();
                ctx.insert("title", "Edit Profile");
                ctx.insert("user", &user);
                ctx.insert("error", &format!("Failed to update profile: {}", e));
                let body = tmpl.render("profile.html", &ctx).unwrap();
                (StatusCode::BAD_REQUEST, Html(body)).into_response()
            }
            Err(_) => Redirect::to("/login").into_response(),
        },
    }
}

/// GET /reset-password?forgot_password=TOKEN
pub async fn reset_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    Query(params): Query<ResetPasswordQuery>,
) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Reset Password");
    ctx.insert("token", &params.forgot_password);

    match tmpl.render("reset_password.html", &ctx) {
        Ok(body) => Html(body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test_token"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=test_token; other=value"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie_single() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token=test_token"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_missing() {
        let headers = HeaderMap::new();
        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_malformed_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("malformed_cookie_without_equals"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_empty_cookie_value() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token="));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn registration_defaults_to_the_public_namespace() {
        assert_eq!(default_namespace(), "public");
    }

    #[test]
    fn a_registration_form_without_a_namespace_lands_in_public() {
        let form: RegisterForm = serde_json::from_str(
            r#"{"email":"a@example.com","username":"a","password":"p","first_login":true}"#,
        )
        .expect("the namespace field is optional");

        assert_eq!(form.namespace, "public");
    }

    #[test]
    fn an_explicit_namespace_on_a_registration_form_is_kept() {
        let form: RegisterForm = serde_json::from_str(
            r#"{"email":"a@example.com","username":"a","password":"p","first_login":true,"namespace":"tenant-a"}"#,
        )
        .expect("an explicit namespace must parse");

        assert_eq!(form.namespace, "tenant-a");
    }

    #[test]
    fn a_bearer_header_with_no_token_after_it_yields_nothing() {
        let mut headers = HeaderMap::new();
        // Exactly "Bearer " and nothing else: the scheme is there but the
        // credential is empty, so there is no token to extract.
        headers.insert("authorization", HeaderValue::from_static("Bearer "));

        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn a_one_character_bearer_token_is_still_extracted() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer x"));

        assert_eq!(extract_bearer_token(&headers), Some("x".to_string()));
    }
}
