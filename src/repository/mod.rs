pub use crate::domain::organization::{NewOrganization, Organization};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Builds a `SET LOCAL search_path` statement for a tenant `namespace`.
///
/// The namespace is a PostgreSQL identifier, which cannot be bound as a query
/// parameter, so it is interpolated — quoted as an identifier with any embedded
/// `"` doubled per the PostgreSQL rules. sqlx 0.9 requires the `AssertSqlSafe`
/// opt-in for a non-`'static` query string; the escaping here is what makes
/// that assertion actually hold on the tenant-isolation boundary.
pub(crate) fn set_search_path_sql(namespace: &str) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(format!(
        "SET LOCAL search_path TO \"{}\"",
        namespace.replace('"', "\"\"")
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub user_id: i64,
    pub external_id: Uuid,
    pub organization_id: i64,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub first_login: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub external_id: Uuid,
    pub organization_id: i64,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub first_login: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub group_id: i64,
    pub external_id: Uuid,
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroup {
    pub external_id: Uuid,
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyEffect::Allow => write!(f, "ALLOW"),
            PolicyEffect::Deny => write!(f, "DENY"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewPolicy {
    pub external_id: Uuid,
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub user_id: i64,
    pub group_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPolicy {
    pub user_id: i64,
    pub policy_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub group_id: i64,
    pub policy_id: i64,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub token_id: i64,
    pub user_id: i64,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewPasswordResetToken {
    pub user_id: i64,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn find_by_email(&self, email: &str, namespace: &str) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str, namespace: &str) -> Result<Option<User>>;
    async fn find_by_id(&self, user_id: i64, namespace: &str) -> Result<Option<User>>;
    async fn insert_user(&self, new_user: NewUser, namespace: &str) -> Result<User>;
    async fn update_user_password(
        &self,
        user_id: i64,
        new_password_hash: &str,
        namespace: &str,
    ) -> Result<()>;
    async fn update_user_profile(
        &self,
        user_id: i64,
        email: &str,
        username: &str,
        namespace: &str,
    ) -> Result<()>;
    async fn set_first_login(&self, user_id: i64, first_login: bool, namespace: &str)
    -> Result<()>;
    async fn get_user_groups(&self, user_id: i64, namespace: &str) -> Result<Vec<Group>>;
    async fn get_user_policies(&self, user_id: i64, namespace: &str) -> Result<Vec<Policy>>;
    async fn get_user_all_policies(&self, user_id: i64, namespace: &str) -> Result<Vec<Policy>>;
    async fn count_users(&self, namespace: &str) -> Result<i64>;
    async fn delete_user(&self, user_id: i64, namespace: &str) -> Result<()>;
}

#[async_trait]
pub trait GroupRepository: Send + Sync + 'static {
    async fn find_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Group>>;
    async fn find_by_id(&self, group_id: i64, namespace: &str) -> Result<Option<Group>>;
    async fn insert_group(&self, new_group: NewGroup, namespace: &str) -> Result<Group>;
    async fn list_groups(&self, organization_id: i64, namespace: &str) -> Result<Vec<Group>>;
    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()>;
    async fn assign_user_to_groups(
        &self,
        user_id: i64,
        group_ids: &[i64],
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        for group_id in group_ids {
            let _ = self
                .assign_user_to_group(user_id, *group_id, assigned_by, namespace)
                .await?;
        }
        Ok(())
    }
    async fn remove_user_from_group(
        &self,
        user_id: i64,
        group_id: i64,
        namespace: &str,
    ) -> Result<()>;
    async fn get_group_policies(&self, group_id: i64, namespace: &str) -> Result<Vec<Policy>>;
}

#[async_trait]
pub trait PolicyRepository: Send + Sync + 'static {
    async fn find_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Policy>>;
    async fn find_by_id(&self, policy_id: i64, namespace: &str) -> Result<Option<Policy>>;
    async fn insert_policy(&self, new_policy: NewPolicy, namespace: &str) -> Result<Policy>;
    async fn list_policies(&self, organization_id: i64, namespace: &str) -> Result<Vec<Policy>>;
    async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()>;
    async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()>;
    async fn remove_policy_from_user(
        &self,
        user_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()>;
    async fn remove_policy_from_group(
        &self,
        group_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()>;
}

#[async_trait]
pub trait PasswordResetRepository: Send + Sync + 'static {
    async fn create_reset_token(
        &self,
        token: NewPasswordResetToken,
        namespace: &str,
    ) -> Result<PasswordResetToken>;
    async fn find_valid_token(
        &self,
        token: &str,
        namespace: &str,
    ) -> Result<Option<PasswordResetToken>>;
    async fn mark_token_used(&self, token_id: i64, namespace: &str) -> Result<()>;
    async fn cleanup_expired_tokens(&self, namespace: &str) -> Result<()>;
}

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct Settings {
    pub settings_id: i32,
    pub organization_id: Option<i64>,
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateSettings {
    pub organization_id: Option<i64>,
    pub key: String,
    pub value: String,
    pub description: Option<String>,
}

#[async_trait]
pub trait SettingsRepository: Send + Sync + 'static {
    async fn create_settings(
        &self,
        settings: CreateSettings,
        namespace: &str,
    ) -> Result<Option<CreateSettings>>;
    async fn get_settings_by_key(&self, key: &str, namespace: &str) -> Result<Option<Settings>>;
    async fn get_setting_by_key_and_org(
        &self,
        key: &str,
        organization_id: Option<i64>,
        namespace: &str,
    ) -> Result<Option<Settings>>;
    async fn get_all_settings(&self, namespace: &str) -> Result<Vec<Settings>>;
    async fn update_settings_by_key(&self, key: &str, value: &str, namespace: &str) -> Result<()>;
    async fn delete_settings_by_key(&self, key: &str, namespace: &str) -> Result<()>;
}

#[async_trait]
pub trait OrganizationRepository: Send + Sync + 'static {
    async fn find_by_name(&self, name: &str) -> Result<Option<Organization>>;
    async fn find_by_id(&self, organization_id: i64) -> Result<Option<Organization>>;
    async fn find_by_namespace(&self, namespace: &str) -> Result<Option<Organization>>;
    async fn insert_organization(&self, new_org: NewOrganization) -> Result<Organization>;
    async fn list_organizations(&self) -> Result<Vec<Organization>>;
    async fn find_by_secret_key(&self, secret_key: Uuid) -> Result<Option<Organization>>;
    async fn rotate_secret_key(&self, organization_id: i64) -> Result<Uuid>;
    async fn delete_organization(&self, organization_id: i64) -> Result<()>;
}

pub mod sqlx_impl;
