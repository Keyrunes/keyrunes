use crate::repository::UserRepository;
use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;

use crate::repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgPolicyRepository, PgSettingsRepository,
    PgUserRepository,
};
use crate::services::{
    group_service::{CreateGroupRequest, GroupService},
    policy_service::{CreatePolicyRequest, PolicyService},
    user_service::{CreateUserRequest, ForgotPasswordRequest, UpdateUserRequest, UserService},
};

use crate::constants::SUPERADMIN_GROUP;
use crate::handler::auth::AuthenticatedUser;
type UserServiceType = UserService<
    PgUserRepository,
    PgGroupRepository,
    PgPasswordResetRepository,
    PgSettingsRepository,
>;
#[allow(dead_code)]
type GroupServiceType = GroupService<PgGroupRepository>;
#[allow(dead_code)]
type PolicyServiceType = PolicyService<PgPolicyRepository>;

#[derive(Serialize)]
pub struct AdminDashboard {
    pub total_users: i64,
    pub total_groups: i64,
    pub total_policies: i64,
    pub current_admin: AdminInfo,
}

#[derive(serde::Deserialize)]
pub struct OrgIdParam {
    #[serde(
        default,
        deserialize_with = "crate::api::deserializers::deserialize_option_string_or_number"
    )]
    pub org_id: Option<i64>,
}

#[derive(Serialize)]
pub struct AdminInfo {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// POST /api/admin/groups
pub async fn create_group(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(group_service): Extension<Arc<GroupServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = payload.organization_id;

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match group_service.create_group(payload, &namespace).await {
        Ok(group) => (StatusCode::CREATED, Json(group)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create group: {:?}", e);
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}

/// POST /api/admin/users
pub async fn create_user(
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Superadmin or admin access required").into_response();
    }

    let org_id = payload.organization_id;

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    let admin_id = if admin.namespace == namespace {
        Some(admin.user_id)
    } else {
        None
    };

    match user_service
        .create_user(payload, admin_id, &namespace)
        .await
    {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create user: {:?}", e);
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}

/// GET /api/admin/dashboard
pub async fn admin_dashboard(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string()) {
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }

    let user_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let group_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let policy_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM policies")
        .fetch_one(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    let dashboard = AdminDashboard {
        total_users: user_count,
        total_groups: group_count,
        total_policies: policy_count,
        current_admin: AdminInfo {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            groups: user.groups,
        },
    };

    (StatusCode::OK, Json(dashboard)).into_response()
}

/// GET /api/admin/users
pub async fn list_users(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !user.groups.contains(&"admin".to_string())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin access required" })),
        )
            .into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &user, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let set_path_query = format!("SET LOCAL search_path TO \"{}\"", namespace);
    if let Err(e) = sqlx::query(&set_path_query).execute(&mut *tx).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let users = match sqlx::query!(
        r#"
        SELECT u.user_id, u.external_id, u.email, u.username, u.first_login, u.created_at,
               COALESCE(array_agg(g.name) FILTER (WHERE g.name IS NOT NULL), ARRAY[]::varchar[]) as "groups!"
        FROM users u
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        GROUP BY u.user_id
        ORDER BY u.created_at DESC
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Database error in list_users: {}", e);
            let error_response: Json<serde_json::Value> = Json(serde_json::json!({ "error": e.to_string() }));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_response,
            )
                .into_response();
        }
    };

    let user_list: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            serde_json::json!({
                "user_id": u.user_id,
                "external_id": u.external_id,
                "email": u.email,
                "username": u.username,
                "first_login": u.first_login,
                "groups": u.groups,
                "created_at": u.created_at
            })
        })
        .collect();

    (StatusCode::OK, Json(user_list)).into_response()
}

/// GET /api/admin/groups
pub async fn list_groups(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(group_service): Extension<Arc<GroupServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !user.groups.contains(&"admin".to_string())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin access required" })),
        )
            .into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &user, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match group_service.list_groups(org_id, &namespace).await {
        Ok(groups) => (StatusCode::OK, Json(groups)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/admin/policies
pub async fn list_policies(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(policy_service): Extension<Arc<PolicyServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !user.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &user, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match policy_service.list_policies(org_id, &namespace).await {
        Ok(policies) => (StatusCode::OK, Json(policies)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /api/admin/policies
pub async fn create_policy(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(policy_service): Extension<Arc<PolicyServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !user.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = payload.organization_id;

    let namespace = match get_org_namespace_safe(&pool, &user, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match policy_service.create_policy(payload, &namespace).await {
        Ok(policy) => (StatusCode::CREATED, Json(policy)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /api/admin/users/:user_id/groups/:group_id
pub async fn assign_user_to_group(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(group_service): Extension<Arc<GroupServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    let assigned_by = if admin.namespace == namespace {
        Some(admin.user_id)
    } else {
        None
    };

    match group_service
        .assign_user_to_group(user_id, group_id, assigned_by, &namespace)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "User assigned to group successfully"
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// DELETE /api/admin/users/:user_id/groups/:group_id
pub async fn remove_user_from_group(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(group_service): Extension<Arc<GroupServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match group_service
        .remove_user_from_group(user_id, group_id, &namespace)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "User removed from group successfully"
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct CheckPermissionRequest {
    #[serde(deserialize_with = "crate::api::deserializers::deserialize_string_or_number")]
    pub user_id: i64,
    pub group_name: String,
    pub resource: String,
    pub action: String,
}

/// POST /api/admin/permissions/check
pub async fn check_permission(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(payload): Json<CheckPermissionRequest>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let policy_repo = Arc::new(PgPolicyRepository::new(pool.clone()));
    let policy_service = PolicyService::new(policy_repo);

    let user_policies = match user_repo
        .get_user_all_policies(payload.user_id, &admin.namespace)
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
        Json(serde_json::json!({
            "user_id": payload.user_id,
            "group_name": payload.group_name,
            "resource": payload.resource,
            "action": payload.action,
            "has_permission": has_permission
        })),
    )
        .into_response()
}

/// DELETE /api/admin/users/:user_id
pub async fn delete_user(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Path(user_id): Path<i64>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    if admin.user_id == user_id {
        return (StatusCode::BAD_REQUEST, "Cannot delete yourself").into_response();
    }

    match user_service.delete_user(user_id, &admin.namespace).await {
        Ok(_) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// PATCH /api/admin/users/:user_id
pub async fn update_user(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(user_id): Path<i64>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
    Json(payload): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match user_service.update_user(user_id, payload, &namespace).await {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /api/admin/users/:user_id/password/reset
pub async fn admin_reset_user_password(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(user_id): Path<i64>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    match user_service.reset_user_password(user_id, &namespace).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /api/admin/users/:user_id/password/reset-email
pub async fn send_password_reset_email(
    Extension(admin): Extension<AuthenticatedUser>,
    Extension(user_service): Extension<Arc<UserServiceType>>,
    Extension(pool): Extension<sqlx::PgPool>,
    Path(user_id): Path<i64>,
    axum::extract::Query(params): axum::extract::Query<OrgIdParam>,
) -> impl IntoResponse {
    if !admin.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !admin.groups.contains(&"admin".to_string())
    {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let org_id = params
        .org_id
        .unwrap_or(crate::constants::DEFAULT_ORGANIZATION_ID);

    let namespace = match get_org_namespace_safe(&pool, &admin, org_id).await {
        Ok(ns) => ns,
        Err(e) => return e.into_response(),
    };

    let user = match user_service.user_repo.find_by_id(user_id, &namespace).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    let req = ForgotPasswordRequest { email: user.email };

    match user_service.forgot_password(req, &namespace).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "Reset email sent"})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_org_namespace_safe(
    pool: &sqlx::PgPool,
    user: &AuthenticatedUser,
    org_id: i64,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let namespace = match sqlx::query_scalar!(
        "SELECT namespace FROM organizations WHERE organization_id = $1",
        org_id
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(ns)) => ns,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Organization {} not found", org_id) })),
            ));
        }
        Err(e) => {
            let error_response: Json<serde_json::Value> =
                Json(serde_json::json!({ "error": e.to_string() }));
            return Err((StatusCode::INTERNAL_SERVER_ERROR, error_response));
        }
    };

    if user.namespace != "public" && user.namespace != namespace {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Access denied" })),
        ));
    }

    Ok(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_dashboard_serialization() {
        let dashboard = AdminDashboard {
            total_users: 10,
            total_groups: 3,
            total_policies: 5,
            current_admin: AdminInfo {
                user_id: 1,
                username: "admin".to_string(),
                email: "admin@example.com".to_string(),
                groups: vec![SUPERADMIN_GROUP.to_string()],
            },
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        assert!(json.contains("total_users"));
        assert!(json.contains("10"));
    }
}
