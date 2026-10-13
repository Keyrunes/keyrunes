use crate::handler::auth::ApiAuthContext;
use crate::repository::User;
use crate::repository::UserRepository;
use crate::repository::sqlx_impl::{PgPolicyRepository, PgUserRepository};
use crate::services::policy_service::PolicyService;
use axum::response::Response;
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct CheckPermissionRequest {
    pub user_id: i64,
    pub resource: String,
    pub action: String,
}

#[derive(Serialize)]
pub struct PermissionResponse {
    pub allowed: bool,
    pub user_id: i64,
    pub resource: String,
    pub action: String,
}

/// Whether an organization-scoped caller may receive a real allow/deny answer
/// for `user`.
///
/// A user that does not exist, or that belongs to a different organization,
/// must be **indistinguishable** from "exists in my org but has no permission".
/// Otherwise the endpoint is an oracle: a holder of a valid organization key can
/// probe `user_id`s and learn which ones exist and which belong to the org, just
/// from the status code. So this returns `true` only when the user is present
/// *and* in the caller's own organization; every other case collapses to the
/// same `allowed: false` answer.
fn org_caller_may_evaluate(user: Option<&User>, org_id: i64) -> bool {
    matches!(user, Some(u) if u.organization_id == org_id)
}

/// The single deny answer returned for every "no" — missing user, wrong org, or
/// a real policy denial — so none of them can be told apart from the outside.
fn deny_response(user_id: i64, resource: &str, action: &str) -> Response {
    (
        StatusCode::OK,
        Json(PermissionResponse {
            allowed: false,
            user_id,
            resource: resource.to_string(),
            action: action.to_string(),
        }),
    )
        .into_response()
}

pub async fn check_permission(
    Extension(auth_context): Extension<ApiAuthContext>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CheckPermissionRequest>,
) -> impl IntoResponse {
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let policy_repo = Arc::new(PgPolicyRepository::new(pool.clone()));
    let policy_service = PolicyService::new(policy_repo);

    let namespace = match &auth_context {
        ApiAuthContext::Organization(org) => org.namespace.clone(),
        ApiAuthContext::Superadmin(user) => user.namespace.clone(),
    };

    let user_opt = match user_repo.find_by_id(payload.user_id, &namespace).await {
        Ok(user) => user,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Resolve the subject without leaking its existence. An organization caller
    // gets a uniform deny for anything that is not its own user (see
    // `org_caller_may_evaluate`); a global superadmin is trusted and may still
    // learn that a user is absent.
    let user = match &auth_context {
        ApiAuthContext::Organization(org) => {
            if !org_caller_may_evaluate(user_opt.as_ref(), org.organization_id) {
                return deny_response(payload.user_id, &payload.resource, &payload.action);
            }
            user_opt.expect("present: org_caller_may_evaluate required Some")
        }
        ApiAuthContext::Superadmin(_) => match user_opt {
            Some(user) => user,
            None => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        },
    };

    let user_policies = match user_repo
        .get_user_all_policies(user.user_id, &namespace)
        .await
    {
        Ok(policies) => policies,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let has_permission = policy_service
        .evaluate_permission(&user_policies, &payload.resource, &payload.action)
        .await;

    (
        StatusCode::OK,
        Json(PermissionResponse {
            allowed: has_permission,
            user_id: payload.user_id,
            resource: payload.resource,
            action: payload.action,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::org_caller_may_evaluate;
    use crate::repository::User;
    use chrono::Utc;
    use uuid::Uuid;

    fn user_in(org_id: i64) -> User {
        User {
            user_id: 1,
            external_id: Uuid::new_v4(),
            organization_id: org_id,
            email: "subject@example.com".to_string(),
            username: "subject".to_string(),
            password_hash: "x".to_string(),
            first_login: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // The three inputs that used to produce three distinguishable HTTP statuses
    // (404 / 403 / 200) must now collapse to two decisions: evaluate, or deny.

    #[test]
    fn a_missing_user_may_not_be_evaluated() {
        // Was: 404 "User not found" — an existence oracle.
        assert!(!org_caller_may_evaluate(None, 1));
    }

    #[test]
    fn a_user_in_another_org_may_not_be_evaluated() {
        // Was: 403 "does not belong" — a cross-org membership oracle.
        let other = user_in(2);
        assert!(!org_caller_may_evaluate(Some(&other), 1));
    }

    #[test]
    fn a_user_in_the_callers_own_org_may_be_evaluated() {
        let own = user_in(1);
        assert!(org_caller_may_evaluate(Some(&own), 1));
    }
}
