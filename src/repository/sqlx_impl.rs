use super::*;
use crate::constants::DEFAULT_NAMESPACE;
use crate::repository::{Group, NewUser, Policy, PolicyEffect, User};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;

pub struct PgUserRepository {
    pub pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_email(&self, email: &str, namespace: &str) -> Result<Option<User>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, organization_id, email, username, password_hash, created_at, first_login, updated_at  FROM users WHERE LOWER(email) = LOWER($1)"#,
            email
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn find_by_username(&self, username: &str, namespace: &str) -> Result<Option<User>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, organization_id, email, username, password_hash, first_login, created_at, updated_at FROM users WHERE username = $1"#,
            username
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn find_by_id(&self, user_id: i64, namespace: &str) -> Result<Option<User>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            User,
            r#"SELECT user_id, external_id, organization_id, email, username, password_hash, first_login, created_at, updated_at FROM users WHERE user_id = $1"#,
            user_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn insert_user(&self, new_user: NewUser, namespace: &str) -> Result<User> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            User,
            r#"INSERT INTO users (external_id, organization_id, email, username, password_hash, first_login) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id, external_id, organization_id, email, username, password_hash, first_login, created_at, updated_at"#,
            new_user.external_id,
            new_user.organization_id,
            new_user.email,
            new_user.username,
            new_user.password_hash,
            new_user.first_login,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn update_user_password(
        &self,
        user_id: i64,
        new_password_hash: &str,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = now() WHERE user_id = $2",
            new_password_hash,
            user_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_user_profile(
        &self,
        user_id: i64,
        email: &str,
        username: &str,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "UPDATE users SET email = $1, username = $2, updated_at = now() WHERE user_id = $3",
            email,
            username,
            user_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn set_first_login(
        &self,
        user_id: i64,
        first_login: bool,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "UPDATE users SET first_login = $1, updated_at = now() WHERE user_id = $2",
            first_login,
            user_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_user_groups(&self, user_id: i64, namespace: &str) -> Result<Vec<Group>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let groups = sqlx::query_as!(
            Group,
            r#"SELECT g.group_id, g.external_id, g.organization_id, g.name, g.description, g.created_at, g.updated_at
               FROM groups g
               INNER JOIN user_groups ug ON g.group_id = ug.group_id
               WHERE ug.user_id = $1"#,
            user_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(groups)
    }

    async fn get_user_policies(&self, user_id: i64, namespace: &str) -> Result<Vec<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let policies = sqlx::query!(
            r#"SELECT p.policy_id, p.external_id, p.organization_id, p.name, p.description, p.resource, p.action, 
               p.effect as "effect_str", p.conditions, p.created_at, p.updated_at
               FROM policies p
               INNER JOIN user_policies up ON p.policy_id = up.policy_id
               WHERE up.user_id = $1"#,
            user_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut result = Vec::new();
        for row in policies {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                organization_id: row.organization_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }

    async fn get_user_all_policies(&self, user_id: i64, namespace: &str) -> Result<Vec<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let recs = sqlx::query_as!(
            Policy,
            r#"SELECT p.policy_id, p.external_id, p.organization_id, p.name, p.description, p.resource, p.action, p.effect as "effect: PolicyEffect", p.conditions, p.created_at, p.updated_at 
               FROM policies p
               WHERE p.policy_id IN (
                   SELECT policy_id FROM user_policies WHERE user_id = $1
               ) OR p.policy_id IN (
                   SELECT gp.policy_id FROM group_policies gp
                   JOIN user_groups ug ON gp.group_id = ug.group_id
                   WHERE ug.user_id = $1
               )"#,
            user_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(recs)
    }

    async fn count_users(&self, namespace: &str) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let count: i64 = sqlx::query_scalar!("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await?
            .unwrap_or(0);

        tx.commit().await?;
        Ok(count)
    }

    async fn delete_user(&self, user_id: i64, namespace: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query!("DELETE FROM users WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow::anyhow!(
                "User with ID {} not found in organization/namespace '{}'",
                user_id,
                namespace
            ));
        }

        tx.commit().await?;
        Ok(())
    }
}

pub struct PgSettingsRepository {
    pub pool: PgPool,
}

impl PgSettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SettingsRepository for PgSettingsRepository {
    async fn create_settings(
        &self,
        settings: CreateSettings,
        namespace: &str,
    ) -> Result<Option<CreateSettings>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            let record = sqlx::query_as!(
                CreateSettings,
                r#"INSERT INTO settings (organization_id, key, value, description) VALUES ($1, $2, $3, $4)
                   RETURNING organization_id, key, value, description"#,
                settings.organization_id,
                settings.key,
                settings.value,
                settings.description,
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(record)
        } else {
            // In tenant schema, no organization_id
            let record = sqlx::query!(
                r#"INSERT INTO settings (key, value, description) VALUES ($1, $2, $3)
                   RETURNING key, value, description"#,
                settings.key,
                settings.value,
                settings.description,
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;

            Ok(record.map(|r| CreateSettings {
                organization_id: None,
                key: r.key,
                value: r.value,
                description: r.description,
            }))
        }
    }

    async fn get_settings_by_key(&self, key: &str, namespace: &str) -> Result<Option<Settings>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            let record = sqlx::query_as!(
                Settings,
                r#"SELECT * FROM settings WHERE key = $1 AND organization_id IS NULL"#,
                key
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(record)
        } else {
            let record = sqlx::query_as!(
                Settings,
                r#"SELECT settings_id, NULL::bigint as organization_id, key, value, description, created_at, updated_at FROM settings WHERE key = $1"#,
                key
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(record)
        }
    }

    async fn get_setting_by_key_and_org(
        &self,
        key: &str,
        organization_id: Option<i64>,
        namespace: &str,
    ) -> Result<Option<Settings>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            let record = match organization_id {
                Some(org_id) => {
                    sqlx::query_as!(
                        Settings,
                        r#"SELECT * FROM settings WHERE key = $1 AND (organization_id = $2 OR organization_id IS NULL) ORDER BY organization_id NULLS LAST LIMIT 1"#,
                        key,
                        org_id
                    )
                    .fetch_optional(&mut *tx)
                    .await?
                }
                None => {
                     sqlx::query_as!(
                        Settings,
                        r#"SELECT * FROM settings WHERE key = $1 AND organization_id IS NULL"#,
                        key
                    )
                    .fetch_optional(&mut *tx)
                    .await?
                }
            };
            tx.commit().await?;
            Ok(record)
        } else {
            let record = sqlx::query_as!(
                Settings,
                r#"SELECT settings_id, NULL::bigint as organization_id, key, value, description, created_at, updated_at FROM settings WHERE key = $1"#,
                key
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(record)
        }
    }

    async fn get_all_settings(&self, namespace: &str) -> Result<Vec<Settings>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            let records = sqlx::query_as!(Settings, r#"SELECT * FROM settings"#)
                .fetch_all(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(records)
        } else {
            let records = sqlx::query_as!(
                 Settings,
                 r#"SELECT settings_id, NULL::bigint as organization_id, key, value, description, created_at, updated_at FROM settings"#
             )
                .fetch_all(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(records)
        }
    }

    async fn update_settings_by_key(
        &self,
        key: &str,
        updated_value: &str,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            sqlx::query!(
                r#"UPDATE settings SET value = $2 WHERE key = $1"#,
                key,
                updated_value
            )
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query!(
                r#"UPDATE settings SET value = $2 WHERE key = $1"#,
                key,
                updated_value
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(())
    }

    async fn delete_settings_by_key(&self, key: &str, namespace: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        if namespace == DEFAULT_NAMESPACE {
            sqlx::query!(r#"DELETE FROM settings WHERE key = $1"#, key,)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query!(r#"DELETE FROM settings WHERE key = $1"#, key,)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;

        Ok(())
    }
}

pub struct PgGroupRepository {
    pub pool: PgPool,
}

impl PgGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupRepository for PgGroupRepository {
    async fn find_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Group>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, organization_id, name, description, created_at, updated_at FROM groups WHERE name = $1 AND organization_id = $2"#,
            name,
            organization_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn find_by_id(&self, group_id: i64, namespace: &str) -> Result<Option<Group>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, organization_id, name, description, created_at, updated_at FROM groups WHERE group_id = $1"#,
            group_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn insert_group(&self, new_group: NewGroup, namespace: &str) -> Result<Group> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            Group,
            r#"INSERT INTO groups (external_id, organization_id, name, description) 
               VALUES ($1, $2, $3, $4) 
               RETURNING group_id, external_id, organization_id, name, description, created_at, updated_at"#,
            new_group.external_id,
            new_group.organization_id,
            new_group.name,
            new_group.description
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn list_groups(&self, organization_id: i64, namespace: &str) -> Result<Vec<Group>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let groups = sqlx::query_as!(
            Group,
            r#"SELECT group_id, external_id, organization_id, name, description, created_at, updated_at FROM groups WHERE organization_id = $1 ORDER BY name"#,
            organization_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(groups)
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "INSERT INTO user_groups (user_id, group_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id,
            group_id,
            assigned_by
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn remove_user_from_group(
        &self,
        user_id: i64,
        group_id: i64,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
            user_id,
            group_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_group_policies(&self, group_id: i64, namespace: &str) -> Result<Vec<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let policies = sqlx::query!(
            r#"SELECT p.policy_id, p.external_id, p.organization_id, p.name, p.description, p.resource, p.action, 
               p.effect as "effect_str", p.conditions, p.created_at, p.updated_at
               FROM policies p
               INNER JOIN group_policies gp ON p.policy_id = gp.policy_id
               WHERE gp.group_id = $1"#,
            group_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut result = Vec::new();
        for row in policies {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                organization_id: row.organization_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }
}

#[allow(dead_code)]
pub struct PgPolicyRepository {
    pub pool: PgPool,
}

#[allow(dead_code)]
impl PgPolicyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyRepository for PgPolicyRepository {
    async fn find_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let row = sqlx::query!(
            r#"SELECT policy_id, external_id, organization_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies WHERE name = $1 AND organization_id = $2"#,
            name,
            organization_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        if let Some(row) = row {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            Ok(Some(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                organization_id: row.organization_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn find_by_id(&self, policy_id: i64, namespace: &str) -> Result<Option<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let row = sqlx::query!(
            r#"SELECT policy_id, external_id, organization_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies WHERE policy_id = $1"#,
            policy_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        if let Some(row) = row {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            Ok(Some(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                organization_id: row.organization_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn insert_policy(&self, new_policy: NewPolicy, namespace: &str) -> Result<Policy> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let effect_str = new_policy.effect.to_string();
        let row = sqlx::query!(
            r#"INSERT INTO policies (external_id, organization_id, name, description, resource, action, effect, conditions) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
               RETURNING policy_id, external_id, organization_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at"#,
            new_policy.external_id,
            new_policy.organization_id,
            new_policy.name,
            new_policy.description,
            new_policy.resource,
            new_policy.action,
            effect_str,
            new_policy.conditions
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let effect = match row.effect_str.as_str() {
            "ALLOW" => PolicyEffect::Allow,
            "DENY" => PolicyEffect::Deny,
            _ => PolicyEffect::Deny,
        };

        Ok(Policy {
            policy_id: row.policy_id,
            external_id: row.external_id,
            organization_id: row.organization_id,
            name: row.name,
            description: row.description,
            resource: row.resource,
            action: row.action,
            effect,
            conditions: row.conditions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn list_policies(&self, organization_id: i64, namespace: &str) -> Result<Vec<Policy>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rows = sqlx::query!(
            r#"SELECT policy_id, external_id, organization_id, name, description, resource, action, 
               effect as "effect_str", conditions, created_at, updated_at 
               FROM policies WHERE organization_id = $1 ORDER BY name"#,
            organization_id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut result = Vec::new();
        for row in rows {
            let effect = match row.effect_str.as_str() {
                "ALLOW" => PolicyEffect::Allow,
                "DENY" => PolicyEffect::Deny,
                _ => PolicyEffect::Deny,
            };

            result.push(Policy {
                policy_id: row.policy_id,
                external_id: row.external_id,
                organization_id: row.organization_id,
                name: row.name,
                description: row.description,
                resource: row.resource,
                action: row.action,
                effect,
                conditions: row.conditions,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(result)
    }

    async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "INSERT INTO user_policies (user_id, policy_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id,
            policy_id,
            assigned_by
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "INSERT INTO group_policies (group_id, policy_id, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            group_id,
            policy_id,
            assigned_by
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn remove_policy_from_user(
        &self,
        user_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "DELETE FROM user_policies WHERE user_id = $1 AND policy_id = $2",
            user_id,
            policy_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn remove_policy_from_group(
        &self,
        group_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "DELETE FROM group_policies WHERE group_id = $1 AND policy_id = $2",
            group_id,
            policy_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

pub struct PgPasswordResetRepository {
    pub pool: PgPool,
}

impl PgPasswordResetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordResetRepository for PgPasswordResetRepository {
    async fn create_reset_token(
        &self,
        token: NewPasswordResetToken,
        namespace: &str,
    ) -> Result<PasswordResetToken> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            PasswordResetToken,
            r#"INSERT INTO password_reset_tokens (user_id, token, expires_at) 
               VALUES ($1, $2, $3) 
               RETURNING token_id, user_id, token, expires_at, used_at, created_at"#,
            token.user_id,
            token.token,
            token.expires_at
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn find_valid_token(
        &self,
        token: &str,
        namespace: &str,
    ) -> Result<Option<PasswordResetToken>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        let rec = sqlx::query_as!(
            PasswordResetToken,
            r#"SELECT token_id, user_id, token, expires_at, used_at, created_at 
               FROM password_reset_tokens 
               WHERE token = $1 AND expires_at > now() AND used_at IS NULL"#,
            token
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn mark_token_used(&self, token_id: i64, namespace: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!(
            "UPDATE password_reset_tokens SET used_at = now() WHERE token_id = $1",
            token_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cleanup_expired_tokens(&self, namespace: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(set_search_path_sql(namespace))
            .execute(&mut *tx)
            .await?;

        sqlx::query!("DELETE FROM password_reset_tokens WHERE expires_at < now()")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

pub struct PgOrganizationRepository {
    pub pool: PgPool,
}

impl PgOrganizationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OrganizationRepository for PgOrganizationRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<Organization>> {
        let rec = sqlx::query_as!(
            Organization,
            r#"SELECT organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at FROM organizations WHERE name = $1"#,
            name
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_id(&self, organization_id: i64) -> Result<Option<Organization>> {
        let rec = sqlx::query_as!(
            Organization,
            r#"SELECT organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at FROM organizations WHERE organization_id = $1"#,
            organization_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn find_by_namespace(&self, namespace: &str) -> Result<Option<Organization>> {
        let rec = sqlx::query_as::<_, Organization>(
            r#"SELECT organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at FROM organizations WHERE namespace = $1"#,
        )
        .bind(namespace)
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn insert_organization(&self, new_org: NewOrganization) -> Result<Organization> {
        let mut tx = self.pool.begin().await?;

        let rec = sqlx::query_as!(
            Organization,
            r#"INSERT INTO organizations (name, description, namespace, base_url) VALUES ($1, $2, $3, $4) RETURNING organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at"#,
            new_org.name,
            new_org.description,
            new_org.namespace,
            new_org.base_url
        )
        .fetch_one(&mut *tx)
        .await?;

        let schema_name = &rec.namespace;
        if !schema_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            tx.rollback().await?;
            return Err(anyhow::anyhow!("Invalid namespace: {}", schema_name));
        }

        // `schema_name` was validated above to be `[A-Za-z0-9_]+`, so the
        // interpolations below carry no injection vector; the tenant init
        // script is a trusted `include_str!` file with only `__ORG_ID__`
        // (an i64) substituted. sqlx 0.9 still requires the `AssertSqlSafe`
        // opt-in for these non-static query strings.
        let create_schema_query = format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", schema_name);
        sqlx::query(sqlx::AssertSqlSafe(create_schema_query))
            .execute(&mut *tx)
            .await?;

        sqlx::query(set_search_path_sql(schema_name))
            .execute(&mut *tx)
            .await?;

        let init_script = include_str!("../../migrations/tenant/001_init_tenant.sql");
        let populated_script = init_script.replace("__ORG_ID__", &rec.organization_id.to_string());
        for statement in populated_script.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(sqlx::AssertSqlSafe(trimmed))
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE \"{}\".groups DROP CONSTRAINT IF EXISTS groups_name_key",
            schema_name
        )))
        .execute(&mut *tx)
        .await?;

        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE \"{}\".groups ADD CONSTRAINT groups_name_org_key UNIQUE (name, organization_id)",
            schema_name
        )))
        .execute(&mut *tx)
        .await
        .ok();

        tx.commit().await?;

        Ok(rec)
    }

    async fn list_organizations(&self) -> Result<Vec<Organization>> {
        let recs = sqlx::query_as!(
            Organization,
            r#"SELECT organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at FROM organizations ORDER BY name"#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(recs)
    }

    async fn find_by_secret_key(&self, secret_key: Uuid) -> Result<Option<Organization>> {
        let rec = sqlx::query_as!(
            Organization,
            r#"SELECT organization_id, external_id, name, description, secret_key, namespace, base_url, created_at, updated_at FROM organizations WHERE secret_key = $1"#,
            secret_key
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    async fn rotate_secret_key(&self, organization_id: i64) -> Result<Uuid> {
        let new_key = Uuid::new_v4();
        sqlx::query!(
            "UPDATE organizations SET secret_key = $1, updated_at = now() WHERE organization_id = $2",
            new_key,
            organization_id
        )
        .execute(&self.pool)
        .await?;
        Ok(new_key)
    }

    async fn delete_organization(&self, organization_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM organizations WHERE organization_id = $1",
            organization_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
