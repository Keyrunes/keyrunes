use crate::constants::{ADMIN_GROUP, SUPERADMIN_GROUP, USERS_GROUP};
use crate::domain::user::{Email, Password};
use crate::repository::{
    CreateSettings, GroupRepository, NewGroup, NewPasswordResetToken, NewUser,
    OrganizationRepository, PasswordResetRepository, Settings, SettingsRepository, UserRepository,
};
use crate::services::email_service::EmailService;
use crate::services::jwt_service::JwtService;
use anyhow::{Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::{Duration, Utc};
use password_hash::rand_core::{OsRng, RngCore};
use password_hash::{PasswordHash, PasswordVerifier};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserResponse {
    pub user_id: i64,
    pub external_id: Uuid,
    #[serde(rename = "id")]
    pub id: Uuid,
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "username")]
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    pub groups: Vec<String>,
    pub first_login: bool,
    pub organization_id: i64,
    pub namespace: String,
}

fn default_true() -> bool {
    true
}

fn deserialize_string_or_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::api::deserializers::deserialize_string_or_number(deserializer)
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    #[serde(deserialize_with = "deserialize_string_or_i64")]
    pub organization_id: i64,
    pub email: Email,
    pub username: String,
    pub password: Password,
    pub groups: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub first_login: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub organization_id: Option<i64>,
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_login: Option<bool>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
    pub requires_password_change: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminChangePasswordRequest {
    pub user_id: i64,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub first_login: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordResetResponse {
    pub temporary_password: String,
}

#[derive(Clone)]
pub struct UserService<
    U: UserRepository,
    G: GroupRepository,
    P: PasswordResetRepository,
    S: SettingsRepository,
    O: OrganizationRepository,
> {
    pub user_repo: Arc<U>,
    pub group_repo: Arc<G>,
    pub org_repo: Arc<O>,
    pub password_reset_repo: Arc<P>,
    pub jwt_service: Arc<JwtService>,
    #[allow(dead_code)]
    pub settings_service: Arc<SettingsService<S>>,
    pub email_service: Option<Arc<EmailService>>,
}

impl<
    U: UserRepository,
    G: GroupRepository,
    P: PasswordResetRepository,
    S: SettingsRepository,
    O: OrganizationRepository,
> UserService<U, G, P, S, O>
{
    /// Creates a new `UserService` instance.
    pub fn new(
        user_repo: Arc<U>,
        group_repo: Arc<G>,
        org_repo: Arc<O>,
        password_reset_repo: Arc<P>,
        jwt_service: Arc<JwtService>,
        settings_service: Arc<SettingsService<S>>,
        email_service: Option<Arc<EmailService>>,
    ) -> Self {
        Self {
            user_repo,
            group_repo,
            org_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            email_service,
        }
    }

    /// Creates a new user in the system.
    ///
    /// # Arguments
    /// * `req` - The user creation request data.
    /// * `admin_id` - Optional ID of the administrator performing the action.
    /// * `namespace` - The organization namespace for tenant isolation.
    pub async fn create_user(
        &self,
        req: CreateUserRequest,
        admin_id: Option<i64>,
        namespace: &str,
    ) -> Result<UserResponse> {
        if self
            .user_repo
            .find_by_email(req.email.as_ref(), namespace)
            .await?
            .is_some()
        {
            return Err(anyhow!("email already registered"));
        }

        if self
            .user_repo
            .find_by_username(&req.username, namespace)
            .await?
            .is_some()
        {
            return Err(anyhow!("username taken"));
        }

        let group_ids = self
            .resolve_group_ids(
                req.groups.unwrap_or_default(),
                req.organization_id,
                namespace,
            )
            .await?;

        let password_hash = self.hash_password(req.password.expose())?;

        let new_user = NewUser {
            external_id: Uuid::new_v4(),
            organization_id: req.organization_id,
            email: req.email.to_string(),
            username: req.username,
            password_hash,
            first_login: req.first_login,
        };

        let user = self.user_repo.insert_user(new_user, namespace).await?;

        self.group_repo
            .assign_user_to_groups(user.user_id, &group_ids[..], admin_id, namespace)
            .await?;

        let groups = self.get_user_group_names(user.user_id, namespace).await?;

        Ok(UserResponse {
            user_id: user.user_id,
            external_id: user.external_id,
            id: user.external_id,
            email: user.email,
            username: user.username,
            password_hash: user.password_hash,
            groups,
            first_login: user.first_login,
            organization_id: user.organization_id,
            namespace: namespace.to_string(),
        })
    }

    /// Registers a new user. If this is the first user in the namespace,
    /// they are automatically assigned to the `superadmin` group.
    ///
    /// # Arguments
    /// * `req` - The registration request data.
    /// * `namespace` - The organization namespace.
    pub async fn register(&self, req: RegisterRequest, namespace: &str) -> Result<AuthResponse> {
        let organization_id = match req.organization_id {
            Some(id) => id,
            None => {
                if namespace == crate::constants::DEFAULT_NAMESPACE {
                    crate::constants::DEFAULT_ORGANIZATION_ID
                } else {
                    self.org_repo
                        .find_by_namespace(namespace)
                        .await?
                        .map(|o| o.organization_id)
                        .ok_or_else(|| {
                            anyhow!("organization not found for namespace: {}", namespace)
                        })?
                }
            }
        };

        let user_count = self.user_repo.count_users(namespace).await?;
        let groups = if let Some(g) = req.group {
            // `register` is reachable from the public routes, so a caller-named
            // group is untrusted input: without this check anyone could post
            // `{"group": "superadmin"}` and be granted it.
            if crate::constants::is_privileged_group(&g) {
                return Err(anyhow!("group '{}' cannot be requested at registration", g));
            }
            Some(vec![g])
        } else if user_count == 0 {
            if namespace == crate::constants::DEFAULT_NAMESPACE {
                Some(vec![SUPERADMIN_GROUP.to_string(), USERS_GROUP.to_string()])
            } else {
                Some(vec![ADMIN_GROUP.to_string(), USERS_GROUP.to_string()])
            }
        } else {
            None
        };

        let user = self
            .create_user(
                CreateUserRequest {
                    organization_id,
                    email: Email::try_from(req.email.as_str())?,
                    username: req.username,
                    password: Password::try_from(req.password.as_str())?,
                    groups,
                    first_login: false,
                },
                None,
                namespace,
            )
            .await?;

        let token = self.jwt_service.generate_token(
            user.user_id,
            &user.email,
            &user.username,
            user.groups.clone(),
            namespace,
            user.organization_id,
        )?;

        let requires_password_change = user.first_login;

        Ok(AuthResponse {
            user,
            token,
            requires_password_change,
        })
    }

    /// Authenticates a user using their email or username.
    ///
    /// # Arguments
    /// * `identity` - The user's email or username.
    /// * `password` - The user's plain-text password.
    /// * `namespace` - The organization namespace.
    pub async fn login(
        &self,
        identity: String,
        password: String,
        namespace: &str,
    ) -> Result<AuthResponse> {
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();

        let user_opt = if email_re.is_match(&identity) {
            self.user_repo.find_by_email(&identity, namespace).await?
        } else {
            self.user_repo
                .find_by_username(&identity, namespace)
                .await?
        };

        if user_opt.is_none() {
            return Err(anyhow!("invalid credentials"));
        }

        let user = user_opt.ok_or_else(|| anyhow!("invalid credentials"))?;

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow!("invalid stored password hash"))?;
        let argon2 = Argon2::default();

        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(anyhow!("invalid credentials"));
        }

        let groups = self.get_user_group_names(user.user_id, namespace).await?;

        let token = self.jwt_service.generate_token(
            user.user_id,
            &user.email,
            &user.username,
            groups.clone(),
            namespace,
            user.organization_id,
        )?;

        Ok(AuthResponse {
            user: UserResponse {
                user_id: user.user_id,
                external_id: user.external_id,
                id: user.external_id,
                email: user.email,
                username: user.username,
                password_hash: user.password_hash,
                groups,
                first_login: user.first_login,
                organization_id: user.organization_id,
                namespace: namespace.to_string(),
            },
            token,
            requires_password_change: user.first_login,
        })
    }

    /// Changes a user's password. Requires the current password for verification.
    pub async fn change_password(
        &self,
        user_id: i64,
        req: ChangePasswordRequest,
        namespace: &str,
    ) -> Result<()> {
        let user = self
            .user_repo
            .find_by_id(user_id, namespace)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;

        Argon2::default()
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .map_err(|_| anyhow!("Invalid current password"))?;

        let _ = Password::try_from(req.new_password.as_str())?;

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let new_hash = argon2
            .hash_password(req.new_password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?
            .to_string();

        self.user_repo
            .update_user_password(user_id, &new_hash, namespace)
            .await?;

        self.user_repo
            .set_first_login(user_id, false, namespace)
            .await?;

        Ok(())
    }

    /// Updates user profile data (email and username).
    pub async fn update_profile(
        &self,
        user_id: i64,
        req: UpdateProfileRequest,
        namespace: &str,
    ) -> Result<UserResponse> {
        let mut user = self
            .user_repo
            .find_by_id(user_id, namespace)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        if let Some(email) = &req.email {
            let _ = Email::try_from(email.as_str())?;
            user.email = email.clone();
        }

        if let Some(username) = &req.username {
            user.username = username.clone();
        }

        self.user_repo
            .update_user_profile(user.user_id, &user.email, &user.username, namespace)
            .await?;

        let groups = self.get_user_group_names(user.user_id, namespace).await?;

        Ok(UserResponse {
            user_id: user.user_id,
            external_id: user.external_id,
            id: user.external_id,
            email: user.email,
            username: user.username,
            password_hash: user.password_hash,
            groups,
            first_login: user.first_login,
            organization_id: user.organization_id,
            namespace: namespace.to_string(),
        })
    }

    /// Initiates a forgot password flow by generating a reset token.
    pub async fn forgot_password(
        &self,
        req: ForgotPasswordRequest,
        namespace: &str,
    ) -> Result<String> {
        let user = self
            .user_repo
            .find_by_email(&req.email, namespace)
            .await?
            .ok_or_else(|| anyhow!("email not found"))?;

        let token = self.generate_reset_token()?;
        let expires_at = Utc::now() + Duration::hours(24);

        let reset_token = NewPasswordResetToken {
            user_id: user.user_id,
            token: token.clone(),
            expires_at,
        };

        self.password_reset_repo
            .create_reset_token(reset_token, namespace)
            .await?;

        if let Some(email_service) = &self.email_service {
            match email_service
                .send_password_reset_email(&req.email, &token)
                .await
            {
                Ok(_) => {
                    tracing::info!("Password reset email sent to {}", req.email);
                }
                Err(e) => {
                    tracing::error!("Failed to send password reset email: {}", e);
                }
            }
        } else {
            let base_url = match self
                .settings_service
                .get_setting_by_key_and_org("BASE_URL", Some(user.organization_id), namespace)
                .await
            {
                Ok(Some(s)) => s.value,
                _ => "http://localhost:3000".to_string(),
            };

            let reset_link = format!("{}/reset-password?forgot_password={}", base_url, token);
            tracing::warn!(
                "⚠️ Email service not configured. Reset Link: {}",
                reset_link
            );
        }

        Ok(token)
    }

    /// Resets a user's password given a valid reset token.
    pub async fn reset_password(&self, req: ResetPasswordRequest, namespace: &str) -> Result<()> {
        let reset_token = self
            .password_reset_repo
            .find_valid_token(&req.token, namespace)
            .await?
            .ok_or_else(|| anyhow!("invalid or expired reset token"))?;

        if req.new_password.len() < crate::constants::MIN_PASSWORD_LENGTH {
            return Err(anyhow!("new password too short"));
        }

        let new_password_hash = self.hash_password(&req.new_password)?;
        self.user_repo
            .update_user_password(reset_token.user_id, &new_password_hash, namespace)
            .await?;

        self.password_reset_repo
            .mark_token_used(reset_token.token_id, namespace)
            .await?;

        Ok(())
    }

    /// Administrative function to change a user's password.
    pub async fn update_password(
        &self,
        req: AdminChangePasswordRequest,
        namespace: &str,
    ) -> Result<()> {
        if req.new_password.len() < crate::constants::MIN_PASSWORD_LENGTH {
            return Err(anyhow!("new password too short"));
        }

        let new_password_hash = self.hash_password(&req.new_password)?;
        self.user_repo
            .update_user_password(req.user_id, &new_password_hash, namespace)
            .await?;

        Ok(())
    }

    /// Finds a user by their username.
    pub async fn find_user_by_username(
        &self,
        username: &str,
        namespace: &str,
    ) -> Option<UserResponse> {
        self.user_repo
            .find_by_username(username, namespace)
            .await
            .ok()
            .flatten()
            .map(|u| UserResponse {
                user_id: u.user_id,
                external_id: u.external_id,
                id: u.external_id,
                email: u.email,
                username: u.username,
                password_hash: u.password_hash,
                groups: Vec::new(), // Groups not loaded here for performance
                first_login: u.first_login,
                organization_id: u.organization_id,
                namespace: namespace.to_string(),
            })
    }

    /// Finds a user by their email.
    pub async fn find_user_by_email(&self, email: &str, namespace: &str) -> Option<UserResponse> {
        self.user_repo
            .find_by_email(email, namespace)
            .await
            .ok()
            .flatten()
            .map(|u| UserResponse {
                user_id: u.user_id,
                external_id: u.external_id,
                id: u.external_id,
                email: u.email,
                username: u.username,
                password_hash: u.password_hash,
                groups: Vec::new(), // Groups not loaded here for performance
                first_login: u.first_login,
                organization_id: u.organization_id,
                namespace: namespace.to_string(),
            })
    }

    /// Refreshes a JWT token.
    pub async fn refresh_token(&self, token: &str) -> Result<String> {
        self.jwt_service.refresh_token(token)
    }

    /// Retrieves user information based on a valid JWT token.
    pub async fn get_user_by_token(&self, token: &str) -> Result<UserResponse> {
        let claims = self.jwt_service.verify_token(token)?;
        let user_id: i64 = claims.sub.parse()?;

        let user = self
            .user_repo
            .find_by_id(user_id, &claims.namespace)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        let groups = self
            .get_user_group_names(user.user_id, &claims.namespace)
            .await?;

        Ok(UserResponse {
            user_id: user.user_id,
            external_id: user.external_id,
            id: user.external_id,
            email: user.email,
            username: user.username,
            password_hash: user.password_hash,
            groups,
            first_login: user.first_login,
            organization_id: user.organization_id,
            namespace: claims.namespace,
        })
    }

    /// Retrieves the names of all groups a user belongs to.
    pub async fn get_user_group_names(&self, user_id: i64, namespace: &str) -> Result<Vec<String>> {
        let groups = self.user_repo.get_user_groups(user_id, namespace).await?;
        Ok(groups.into_iter().map(|g| g.name).collect())
    }

    /// Updates a user's information from an administrative context.
    pub async fn update_user(
        &self,
        user_id: i64,
        req: UpdateUserRequest,
        namespace: &str,
    ) -> Result<UserResponse> {
        let mut user = self
            .user_repo
            .find_by_id(user_id, namespace)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        if let Some(email) = &req.email {
            Email::try_from(email.as_str())?;
            user.email = email.clone();
        }

        if let Some(username) = &req.username {
            user.username = username.clone();
        }

        self.user_repo
            .update_user_profile(user.user_id, &user.email, &user.username, namespace)
            .await?;

        if let Some(first_login) = req.first_login {
            self.user_repo
                .set_first_login(user.user_id, first_login, namespace)
                .await?;
            user.first_login = first_login;
        }

        let groups = self.get_user_group_names(user.user_id, namespace).await?;

        Ok(UserResponse {
            user_id: user.user_id,
            external_id: user.external_id,
            id: user.external_id,
            email: user.email,
            username: user.username,
            password_hash: user.password_hash,
            groups,
            first_login: user.first_login,
            organization_id: user.organization_id,
            namespace: namespace.to_string(),
        })
    }

    /// Deletes a user from the system.
    pub async fn delete_user(&self, user_id: i64, namespace: &str) -> Result<()> {
        self.user_repo.delete_user(user_id, namespace).await?;
        Ok(())
    }

    /// Administrative function to reset a user's password to a temporary one.
    pub async fn reset_user_password(
        &self,
        user_id: i64,
        namespace: &str,
    ) -> Result<PasswordResetResponse> {
        let temp_password = self.generate_temp_password();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(temp_password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?
            .to_string();

        self.user_repo
            .update_user_password(user_id, &password_hash, namespace)
            .await?;

        self.user_repo
            .set_first_login(user_id, true, namespace)
            .await?;

        Ok(PasswordResetResponse {
            temporary_password: temp_password,
        })
    }

    /// Generates a secure temporary password.
    fn generate_temp_password(&self) -> String {
        let mut rng = OsRng;
        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        abcdefghijklmnopqrstuvwxyz\
                        0123456789\
                        )(*&^%$#@!~";
        (0..12)
            .map(|_| {
                let idx = rng.next_u32() as usize % charset.len();
                charset[idx] as char
            })
            .collect()
    }

    /// Hashes a plain-text password using Argon2.
    fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?
            .to_string())
    }

    fn generate_reset_token(&self) -> Result<String> {
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| anyhow!("failed to fill bytes: {}", e))?;
        Ok(hex::encode(bytes))
    }

    #[allow(dead_code)]
    pub async fn cleanup_expired_tokens(&self, namespace: &str) -> Result<()> {
        self.password_reset_repo
            .cleanup_expired_tokens(namespace)
            .await
    }

    pub(crate) async fn resolve_group_ids(
        &self,
        mut groups: Vec<String>,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Vec<i64>> {
        if groups.is_empty() {
            groups.push(crate::constants::USERS_GROUP.to_string());
        }

        let mut group_ids = Vec::new();

        for group_name in groups {
            let group = group_name.trim();

            let found_group = self
                .group_repo
                .find_by_name(group, organization_id, namespace)
                .await?;

            if let Some(g) = found_group {
                group_ids.push(g.group_id);
            } else if group == USERS_GROUP {
                // Auto-create users group if it doesn't exist
                let new_group = NewGroup {
                    external_id: Uuid::new_v4(),
                    organization_id,
                    name: USERS_GROUP.to_string(),
                    description: Some("Standard users of the organization".to_string()),
                };
                let users_group = self.group_repo.insert_group(new_group, namespace).await?;
                group_ids.push(users_group.group_id);
            } else if group == ADMIN_GROUP {
                // Auto-create admin group if it doesn't exist
                let new_group = NewGroup {
                    external_id: Uuid::new_v4(),
                    organization_id,
                    name: ADMIN_GROUP.to_string(),
                    description: Some("Administrators of the organization".to_string()),
                };
                let admin_group = self.group_repo.insert_group(new_group, namespace).await?;
                group_ids.push(admin_group.group_id);
            } else {
                return Err(anyhow!("invalid group specified: `{}`", group));
            }
        }

        Ok(group_ids)
    }
}

#[allow(dead_code)]
pub struct SettingsService<S: SettingsRepository> {
    settings_repo: Arc<S>,
}

#[allow(dead_code)]
impl<S: SettingsRepository> SettingsService<S> {
    pub fn new(settings_repo: Arc<S>) -> Self {
        Self { settings_repo }
    }

    pub async fn get_all_settings(&self, namespace: &str) -> Result<Vec<Settings>> {
        self.settings_repo.get_all_settings(namespace).await
    }

    pub async fn find_settings_by_key(&self, key: &str, namespace: &str) -> Result<Settings> {
        let record = self
            .settings_repo
            .get_settings_by_key(key, namespace)
            .await?;

        if record.is_none() {
            return Err(anyhow!("Settings with {} not found", key));
        }

        Ok(record.unwrap())
    }

    pub async fn get_setting_by_key_and_org(
        &self,
        key: &str,
        organization_id: Option<i64>,
        namespace: &str,
    ) -> Result<Option<Settings>> {
        self.settings_repo
            .get_setting_by_key_and_org(key, organization_id, namespace)
            .await
    }

    pub async fn insert_settings(
        &self,
        key: String,
        value: String,
        description: String,
        namespace: &str,
    ) -> Result<()> {
        let record = self
            .settings_repo
            .get_settings_by_key(key.as_str(), namespace)
            .await?;

        if record.is_some() {
            return Err(anyhow!("Settings with {} already created", key));
        }

        self.settings_repo
            .create_settings(
                CreateSettings {
                    organization_id: None,
                    key,
                    value,
                    description: Some(description),
                },
                namespace,
            )
            .await?;

        Ok(())
    }

    pub async fn update_settings(&self, key: String, value: String, namespace: &str) -> Result<()> {
        self.settings_repo
            .update_settings_by_key(key.as_str(), value.as_str(), namespace)
            .await?;

        Ok(())
    }

    pub async fn delete_settings(&self, key: String, namespace: &str) -> Result<()> {
        self.settings_repo
            .delete_settings_by_key(key.as_str(), namespace)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{
        CreateSettings, Group, NewGroup, NewOrganization, Organization, Policy, Settings, User,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[allow(dead_code)]
    struct MockUserRepository {
        users: Mutex<Vec<User>>,
        groups: Mutex<Vec<(i64, i64)>>,
    }

    #[allow(dead_code)]
    impl MockUserRepository {
        fn new() -> Self {
            Self {
                users: Mutex::new(Vec::new()),
                groups: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_email(&self, email: &str, _namespace: &str) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.email == email).cloned())
        }

        async fn find_by_username(&self, username: &str, _namespace: &str) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.username == username).cloned())
        }

        async fn find_by_id(&self, user_id: i64, _namespace: &str) -> Result<Option<User>> {
            let users = self.users.lock().unwrap();
            Ok(users.iter().find(|u| u.user_id == user_id).cloned())
        }

        async fn insert_user(&self, new_user: NewUser, _namespace: &str) -> Result<User> {
            let mut users = self.users.lock().unwrap();
            let user = User {
                user_id: (users.len() + 1) as i64,
                external_id: new_user.external_id,
                organization_id: new_user.organization_id,
                email: new_user.email,
                username: new_user.username,
                password_hash: new_user.password_hash,
                first_login: new_user.first_login,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            users.push(user.clone());
            Ok(user)
        }

        async fn update_user_password(
            &self,
            user_id: i64,
            new_password_hash: &str,
            _namespace: &str,
        ) -> Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.password_hash = new_password_hash.to_string();
                user.updated_at = Utc::now();
            }
            Ok(())
        }

        async fn update_user_profile(
            &self,
            user_id: i64,
            email: &str,
            username: &str,
            _namespace: &str,
        ) -> Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.email = email.to_string();
                user.username = username.to_string();
                user.updated_at = Utc::now();
            }
            Ok(())
        }

        async fn set_first_login(
            &self,
            user_id: i64,
            first_login: bool,
            _namespace: &str,
        ) -> Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.first_login = first_login;
                user.updated_at = Utc::now();
            }
            Ok(())
        }

        async fn get_user_groups(&self, _user_id: i64, _namespace: &str) -> Result<Vec<Group>> {
            Ok(Vec::new()) // Simplified
        }

        async fn delete_user(&self, _user_id: i64, _namespace: &str) -> Result<()> {
            Ok(())
        }
        async fn count_users(&self, _namespace: &str) -> Result<i64> {
            Ok(0)
        }
        async fn get_user_policies(&self, _user_id: i64, _namespace: &str) -> Result<Vec<Policy>> {
            Ok(Vec::new())
        }
        async fn get_user_all_policies(
            &self,
            _user_id: i64,
            _namespace: &str,
        ) -> Result<Vec<Policy>> {
            Ok(Vec::new())
        }
    }

    #[allow(dead_code)]
    struct MockGroupRepository;

    #[async_trait]
    impl GroupRepository for MockGroupRepository {
        async fn find_by_name(
            &self,
            name: &str,
            organization_id: i64,
            _namespace: &str,
        ) -> Result<Option<Group>> {
            Ok(Some(Group {
                group_id: 1,
                external_id: Uuid::new_v4(),
                organization_id,
                name: name.to_string(),
                description: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }))
        }

        async fn find_by_id(&self, _group_id: i64, _namespace: &str) -> Result<Option<Group>> {
            Ok(None)
        }
        async fn insert_group(&self, _new_group: NewGroup, _namespace: &str) -> Result<Group> {
            unimplemented!()
        }
        async fn list_groups(&self, _org_id: i64, _namespace: &str) -> Result<Vec<Group>> {
            Ok(Vec::new())
        }
        async fn assign_user_to_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn assign_user_to_groups(
            &self,
            _user_id: i64,
            _group_ids: &[i64],
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn remove_user_from_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _namespace: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_group_policies(
            &self,
            _group_id: i64,
            _namespace: &str,
        ) -> Result<Vec<Policy>> {
            Ok(Vec::new())
        }
    }

    #[allow(dead_code)]
    struct MockPasswordResetRepository;

    #[async_trait]
    impl PasswordResetRepository for MockPasswordResetRepository {
        async fn create_reset_token(
            &self,
            _token: NewPasswordResetToken,
            _namespace: &str,
        ) -> Result<crate::repository::PasswordResetToken> {
            unimplemented!()
        }
        async fn find_valid_token(
            &self,
            _token: &str,
            _namespace: &str,
        ) -> Result<Option<crate::repository::PasswordResetToken>> {
            Ok(None)
        }
        async fn mark_token_used(&self, _token_id: i64, _namespace: &str) -> Result<()> {
            Ok(())
        }
        async fn cleanup_expired_tokens(&self, _namespace: &str) -> Result<()> {
            Ok(())
        }
    }

    #[allow(dead_code)]
    struct MockSettingsRepository;
    #[async_trait]
    impl SettingsRepository for MockSettingsRepository {
        async fn get_all_settings(&self, _namespace: &str) -> Result<Vec<Settings>> {
            Ok(Vec::new())
        }
        async fn get_settings_by_key(
            &self,
            _key: &str,
            _namespace: &str,
        ) -> Result<Option<Settings>> {
            Ok(None)
        }
        async fn create_settings(
            &self,
            _s: CreateSettings,
            _ns: &str,
        ) -> Result<Option<CreateSettings>> {
            Ok(None)
        }
        async fn update_settings_by_key(&self, _k: &str, _v: &str, _ns: &str) -> Result<()> {
            Ok(())
        }
        async fn delete_settings_by_key(&self, _k: &str, _ns: &str) -> Result<()> {
            Ok(())
        }
        async fn get_setting_by_key_and_org(
            &self,
            _k: &str,
            _o: Option<i64>,
            _ns: &str,
        ) -> Result<Option<Settings>> {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    struct MockOrganizationRepository;
    #[async_trait]
    impl OrganizationRepository for MockOrganizationRepository {
        async fn find_by_name(&self, _name: &str) -> Result<Option<Organization>> {
            Ok(None)
        }
        async fn find_by_id(&self, _id: i64) -> Result<Option<Organization>> {
            Ok(None)
        }
        async fn find_by_namespace(&self, _namespace: &str) -> Result<Option<Organization>> {
            Ok(Some(Organization {
                organization_id: 1,
                external_id: Uuid::new_v4(),
                name: "test".to_string(),
                description: None,
                namespace: "test".to_string(),
                base_url: None,
                secret_key: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }))
        }
        async fn insert_organization(&self, _new_org: NewOrganization) -> Result<Organization> {
            unimplemented!()
        }
        async fn list_organizations(&self) -> Result<Vec<Organization>> {
            Ok(Vec::new())
        }
        async fn find_by_secret_key(&self, _key: Uuid) -> Result<Option<Organization>> {
            Ok(None)
        }
        async fn rotate_secret_key(&self, _id: i64) -> Result<Uuid> {
            Ok(Uuid::new_v4())
        }
        async fn delete_organization(&self, _id: i64) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_user_success() {
        // Setup
        let user_repo = Arc::new(MockUserRepository::new());
        let group_repo = Arc::new(MockGroupRepository);
        let password_reset_repo = Arc::new(MockPasswordResetRepository);
        let jwt_secret = "test_secret";
        let jwt_service = Arc::new(JwtService::new(jwt_secret));
        let settings_repo = Arc::new(MockSettingsRepository);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let org_repo = Arc::new(MockOrganizationRepository);

        let service = UserService::new(
            user_repo,
            group_repo,
            org_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        let req = CreateUserRequest {
            organization_id: 1,
            email: Email::try_from("test@example.com").unwrap(),
            username: "testuser".to_string(),
            password: Password::try_from("Password123!").unwrap(),
            groups: None,
            first_login: true,
        };

        // Act
        let result = service.create_user(req, None, "default").await;

        // Assert
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.namespace, "default");
    }

    #[tokio::test]
    async fn test_resolve_group_ids_auto_create() {
        // Setup
        let user_repo = Arc::new(MockUserRepository::new());
        let password_reset_repo = Arc::new(MockPasswordResetRepository);
        let jwt_service = Arc::new(JwtService::new("secret"));
        let settings_repo = Arc::new(MockSettingsRepository);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let org_repo = Arc::new(MockOrganizationRepository);

        // Custom MockGroupRepository that fails find_by_name but implements insert_group
        struct AutoCreateGroupMock;
        #[async_trait]
        impl GroupRepository for AutoCreateGroupMock {
            async fn find_by_name(&self, _n: &str, _oid: i64, _ns: &str) -> Result<Option<Group>> {
                Ok(None)
            }
            async fn insert_group(&self, ng: NewGroup, _ns: &str) -> Result<Group> {
                Ok(Group {
                    group_id: 123,
                    external_id: ng.external_id,
                    organization_id: ng.organization_id,
                    name: ng.name,
                    description: ng.description,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            }
            async fn find_by_id(&self, _: i64, _: &str) -> Result<Option<Group>> {
                Ok(None)
            }
            async fn list_groups(&self, _: i64, _: &str) -> Result<Vec<Group>> {
                Ok(Vec::new())
            }
            async fn assign_user_to_group(
                &self,
                _: i64,
                _: i64,
                _: Option<i64>,
                _: &str,
            ) -> Result<()> {
                Ok(())
            }
            async fn remove_user_from_group(&self, _: i64, _: i64, _: &str) -> Result<()> {
                Ok(())
            }
            async fn get_group_policies(&self, _: i64, _: &str) -> Result<Vec<Policy>> {
                Ok(Vec::new())
            }
        }

        let group_repo = Arc::new(AutoCreateGroupMock);
        let service = UserService::new(
            user_repo,
            group_repo,
            org_repo,
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Act
        let result = service
            .resolve_group_ids(vec!["users".to_string(), "admin".to_string()], 1, "test")
            .await;

        // Assert
        assert!(result.is_ok());
        let ids = result.unwrap();
        assert_eq!(ids, vec![123, 123]); // Both match the same insert logic in this simplified mock

        // Test with whitespace
        let result_ws = service
            .resolve_group_ids(vec!["  users  ".to_string()], 1, "test")
            .await;
        assert!(result_ws.is_ok());
        assert_eq!(result_ws.unwrap(), vec![123]);
    }
}
