use axum::{
    body::Body,
    extract::{Extension, Request},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::constants::{ADMIN_GROUP, SUPERADMIN_GROUP};
use crate::handler::errors::ErrorResponse;
use crate::repository::sqlx_impl::{PgGroupRepository, PgOrganizationRepository};
use crate::services::jwt_service::{Claims, JwtService};
use crate::services::organization_service::OrganizationService;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: i64,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub namespace: String,
    pub organization_id: i64,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub.parse().unwrap_or(0),
            email: claims.email,
            username: claims.username,
            groups: claims.groups,
            namespace: claims.namespace,
            organization_id: claims.organization_id,
        }
    }
}

/// Middleware that requires JWT authentication
pub async fn require_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    match jwt_service.verify_token(&token) {
        Ok(claims) => {
            let user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(_) => ErrorResponse::unauthorized("Invalid or expired token").into_response(),
    }
}

/// Middleware that optionally extracts user from JWT if present
#[allow(dead_code)]
pub async fn optional_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(token) = extract_bearer_token(&headers)
        && let Ok(claims) = jwt_service.verify_token(&token)
    {
        let user = AuthenticatedUser::from(claims);
        request.extensions_mut().insert(user);
    }

    next.run(request).await
}

/// Middleware that requires specific groups
#[allow(dead_code)]
pub fn require_groups(
    required_groups: Vec<String>,
) -> impl Clone
+ Fn(
    Extension<AuthenticatedUser>,
    Request<Body>,
    Next,
) -> Pin<Box<dyn Future<Output = Response> + Send>> {
    let required_groups: Vec<Arc<String>> = required_groups.into_iter().map(Arc::new).collect();

    move |Extension(user): Extension<AuthenticatedUser>, request: Request<Body>, next: Next| {
        let required_groups = required_groups.clone();

        Box::pin(async move {
            let has_required_group = required_groups
                .iter()
                .any(|group| user.groups.iter().any(|ug| ug == &**group));

            if has_required_group {
                next.run(request).await
            } else {
                ErrorResponse::forbidden("Insufficient permissions - required group not found")
                    .into_response()
            }
        })
    }
}

/// Middleware that requires superadmin or admin group
pub async fn require_superadmin(
    Extension(user): Extension<AuthenticatedUser>,
    request: Request,
    next: Next,
) -> Response {
    if user.groups.contains(&SUPERADMIN_GROUP.to_string())
        || user.groups.contains(&ADMIN_GROUP.to_string())
    {
        next.run(request).await
    } else {
        ErrorResponse::forbidden("Superadmin or Admin access required").into_response()
    }
}

use crate::domain::organization::Organization;

#[derive(Clone)]
pub enum ApiAuthContext {
    Organization(Organization),
    Superadmin(AuthenticatedUser),
}

/// Middleware that requires X-Organization-Key header OR superadmin permissions
pub async fn require_org_key_or_superadmin(
    Extension(org_service): Extension<
        Arc<OrganizationService<PgOrganizationRepository, PgGroupRepository>>,
    >,
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(key) = headers.get("X-Organization-Key") {
        let api_key = match key.to_str() {
            Ok(k) => k,
            Err(_) => return ErrorResponse::unauthorized("Invalid API Key format").into_response(),
        };

        let secret_key = match Uuid::parse_str(api_key) {
            Ok(uuid) => uuid,
            Err(_) => {
                return ErrorResponse::unauthorized("Invalid API Key format (must be UUID)")
                    .into_response();
            }
        };

        return match org_service.get_organization_by_secret_key(secret_key).await {
            Ok(Some(org)) => {
                request
                    .extensions_mut()
                    .insert(ApiAuthContext::Organization(org));
                next.run(request).await
            }
            Ok(None) => ErrorResponse::unauthorized("Invalid API Key").into_response(),
            Err(e) => {
                tracing::error!("Database error extracting org key: {:?}", e);
                ErrorResponse::internal_server_error("Internal server error").into_response()
            }
        };
    }

    if let Some(token) = extract_bearer_token(&headers)
        && let Ok(claims) = jwt_service.verify_token(&token)
    {
        let user = AuthenticatedUser::from(claims);
        if user.groups.contains(&SUPERADMIN_GROUP.to_string()) {
            request
                .extensions_mut()
                .insert(ApiAuthContext::Superadmin(user));
            return next.run(request).await;
        }
    }

    ErrorResponse::unauthorized("Missing X-Organization-Key header or valid Superadmin token")
        .into_response()
}

/// Extract Bearer token from Authorization header or cookies.
///
/// Shared with the HTML views: both entry points must agree on what counts
/// as a token, and two copies of this parser would be free to drift apart.
pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
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
    use crate::constants::USERS_GROUP;
    use axum::http::{HeaderMap, HeaderValue};
    use exhaustive::{Exhaustive, exhaustive_test};

    #[test]
    fn test_extract_bearer_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=test123; other=value"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_cookie_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token=abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_empty_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token="));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
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
    fn test_extract_bearer_token_bearer_too_short() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer "));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_authenticated_user_from_claims() {
        let claims = Claims {
            sub: "123".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            groups: vec![USERS_GROUP.to_string(), "admin".to_string()],
            namespace: "test_ns".to_string(),
            organization_id: 1,
            exp: 1234567890,
            iat: 1234567890,
            iss: "keyrunes".to_string(),
        };

        let user = AuthenticatedUser::from(claims);
        assert_eq!(user.user_id, 123);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.username, "testuser");
        assert_eq!(user.groups, vec![USERS_GROUP, "admin"]);
        assert_eq!(user.namespace, "test_ns");
    }

    // ---------------------------------------------------------------------
    // Exhaustive token extraction.
    //
    // `extract_bearer_token` is the front door: every authenticated request
    // passes through it, and it reads from two independent sources. The cross
    // product of their shapes is enumerated so the precedence between them,
    // and every rejection, is pinned rather than sampled.
    // ---------------------------------------------------------------------

    /// The token an accepted case must yield from the Authorization header.
    const HEADER_TOKEN: &str = "header-token";
    /// The token an accepted case must yield from the cookie.
    const COOKIE_TOKEN: &str = "cookie-token";

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum AuthHeader {
        Absent,
        /// A well-formed `Bearer <token>`.
        Bearer,
        /// `Bearer ` with nothing after it.
        BearerEmpty,
        /// `Bearer` with no trailing space at all.
        BearerNoSpace,
        /// Lowercase scheme. RFC 7235 calls the scheme case-insensitive, but
        /// this implementation matches it case-sensitively.
        LowercaseBearer,
        /// A different auth scheme.
        Basic,
        /// A bare token with no scheme.
        SchemeLess,
        /// Bytes that are not valid UTF-8, so `to_str()` fails.
        NonUtf8,
    }

    impl AuthHeader {
        fn value(self) -> Option<HeaderValue> {
            match self {
                AuthHeader::Absent => None,
                AuthHeader::Bearer => Some(HeaderValue::from_static("Bearer header-token")),
                AuthHeader::BearerEmpty => Some(HeaderValue::from_static("Bearer ")),
                AuthHeader::BearerNoSpace => Some(HeaderValue::from_static("Bearer")),
                AuthHeader::LowercaseBearer => {
                    Some(HeaderValue::from_static("bearer header-token"))
                }
                AuthHeader::Basic => Some(HeaderValue::from_static("Basic aGk6dGhlcmU=")),
                AuthHeader::SchemeLess => Some(HeaderValue::from_static("header-token")),
                AuthHeader::NonUtf8 => Some(HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap()),
            }
        }

        /// Whether this header alone yields a token.
        fn yields_token(self) -> bool {
            self == AuthHeader::Bearer
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum CookieHeader {
        Absent,
        /// `jwt_token=<token>` on its own.
        Only,
        /// The token cookie after another one.
        AfterAnother,
        /// The token cookie before another one.
        BeforeAnother,
        /// Present but with an empty value.
        EmptyValue,
        /// A cookie whose name merely ends with `jwt_token`, which must not
        /// be mistaken for it.
        NameSuffixTrap,
        /// Some other cookie entirely.
        Unrelated,
        NonUtf8,
    }

    impl CookieHeader {
        fn value(self) -> Option<HeaderValue> {
            match self {
                CookieHeader::Absent => None,
                CookieHeader::Only => Some(HeaderValue::from_static("jwt_token=cookie-token")),
                CookieHeader::AfterAnother => Some(HeaderValue::from_static(
                    "theme=dark; jwt_token=cookie-token",
                )),
                CookieHeader::BeforeAnother => Some(HeaderValue::from_static(
                    "jwt_token=cookie-token; theme=dark",
                )),
                CookieHeader::EmptyValue => Some(HeaderValue::from_static("jwt_token=")),
                CookieHeader::NameSuffixTrap => {
                    Some(HeaderValue::from_static("not_jwt_token=cookie-token"))
                }
                CookieHeader::Unrelated => Some(HeaderValue::from_static("theme=dark")),
                CookieHeader::NonUtf8 => Some(HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap()),
            }
        }

        fn yields_token(self) -> bool {
            matches!(
                self,
                CookieHeader::Only | CookieHeader::AfterAnother | CookieHeader::BeforeAnother
            )
        }
    }

    fn headers_for(auth: AuthHeader, cookie: CookieHeader) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = auth.value() {
            headers.insert("authorization", value);
        }
        if let Some(value) = cookie.value() {
            headers.insert("cookie", value);
        }
        headers
    }

    /// All 8 x 8 = 64 combinations of the two sources.
    ///
    /// The Authorization header takes precedence; the cookie is consulted only
    /// when the header yields nothing. Anything else yields no token at all,
    /// and no shape may panic.
    #[exhaustive_test]
    fn extract_bearer_token_prefers_the_header_over_the_cookie(
        auth: AuthHeader,
        cookie: CookieHeader,
    ) {
        let extracted = extract_bearer_token(&headers_for(auth, cookie));

        let expected = if auth.yields_token() {
            Some(HEADER_TOKEN.to_string())
        } else if cookie.yields_token() {
            Some(COOKIE_TOKEN.to_string())
        } else {
            None
        };

        assert_eq!(extracted, expected, "auth {auth:?} with cookie {cookie:?}");
    }

    /// A malformed Authorization header must fall through to the cookie rather
    /// than swallow the request: a browser session survives a stray header.
    #[exhaustive_test]
    fn a_rejected_auth_header_still_lets_the_cookie_through(auth: AuthHeader) {
        if auth.yields_token() {
            return;
        }

        assert_eq!(
            extract_bearer_token(&headers_for(auth, CookieHeader::Only)),
            Some(COOKIE_TOKEN.to_string()),
            "{auth:?} blocked the cookie"
        );
    }
}
