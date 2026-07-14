mod common;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use common::factories::{GroupFactory, OrganizationFactory, UserFactory};
use keyrunes::UserGroup;
use keyrunes::constants::DEFAULT_NAMESPACE;
use keyrunes::domain::user::{Email, Password};
use keyrunes::group_service::{CreateGroupRequest, GroupService};
use keyrunes::repository::{
    CreateSettings, Group, NewOrganization, NewUser, Organization, OrganizationRepository, Policy,
    Settings, User, UserRepository,
};
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::user_service::{CreateUserRequest, SettingsService};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type Store<T> = Arc<Mutex<Vec<T>>>;
type GroupStore = Store<Group>;
type UserGroupStore = Store<UserGroup>;
type SettingsStore = Store<Settings>;
type UserServiceType = UserService<
    MockRepo,
    MockGroupRepository,
    MockPasswordResetRepository,
    MockSettingsRepository,
    MockOrganizationRepository,
>;

fn create_stores() -> (GroupStore, UserGroupStore) {
    let group_store = Arc::new(Mutex::new(Vec::new()));
    let user_group_store = Arc::new(Mutex::new(Vec::new()));

    group_store.lock().unwrap().push(GroupFactory::create_group(
        1,
        keyrunes::constants::SUPERADMIN_GROUP.to_string(),
        Some("Admin group".to_string()),
        keyrunes::constants::DEFAULT_ORGANIZATION_ID,
    ));

    group_store.lock().unwrap().push(GroupFactory::create_group(
        2,
        keyrunes::constants::USERS_GROUP.to_string(),
        Some("User group".to_string()),
        keyrunes::constants::DEFAULT_ORGANIZATION_ID,
    ));

    group_store.lock().unwrap().push(GroupFactory::create_group(
        3,
        keyrunes::constants::ADMIN_GROUP.to_string(),
        Some("Admin group for Org 2".to_string()),
        2,
    ));

    group_store.lock().unwrap().push(GroupFactory::create_group(
        4,
        keyrunes::constants::USERS_GROUP.to_string(),
        Some("User group for Org 2".to_string()),
        2,
    ));

    (group_store, user_group_store)
}

struct MockRepo {
    users: Mutex<Vec<User>>,
    group_store: GroupStore,
    user_group_store: UserGroupStore,
}

impl MockRepo {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            users: Mutex::new(Vec::new()),
            group_store,
            user_group_store,
        }
    }
}

#[async_trait]
impl UserRepository for MockRepo {
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

    async fn get_user_groups(&self, user_id: i64, _namespace: &str) -> Result<Vec<Group>> {
        let groups = self.group_store.lock().unwrap();
        let user_groups = self.user_group_store.lock().unwrap();
        let user_groups: Vec<Group> = user_groups
            .iter()
            .filter(|ug| ug.user_id == user_id)
            .map(|ug| {
                groups
                    .iter()
                    .find(|&g| ug.group_id == g.group_id)
                    .cloned()
                    .unwrap()
            })
            .collect();
        Ok(user_groups)
    }

    async fn get_user_policies(&self, _user_id: i64, _namespace: &str) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }

    async fn get_user_all_policies(&self, _user_id: i64, _namespace: &str) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }

    async fn count_users(&self, namespace: &str) -> Result<i64> {
        let users = self.users.lock().unwrap();
        let count = match namespace {
            DEFAULT_NAMESPACE => users.iter().filter(|u| u.organization_id == 1).count(),
            "org_2" => users.iter().filter(|u| u.organization_id == 2).count(),
            _ => users.iter().count(), // Fallback
        };
        Ok(count as i64)
    }

    async fn delete_user(&self, user_id: i64, _namespace: &str) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        users.retain(|u| u.user_id != user_id);
        Ok(())
    }
}

#[tokio::test]
async fn test_delete_user() {
    // Setup
    let service = helper_service();
    let user_data = UserFactory::build();
    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
        group: None,
    };
    let auth_response = service.register(req, DEFAULT_NAMESPACE).await.unwrap();
    let user_id = auth_response.user.user_id;

    // Act
    let delete_result = service.delete_user(user_id, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(delete_result.is_ok());

    let find_result = service
        .find_user_by_email(&user_data.email, DEFAULT_NAMESPACE)
        .await;
    assert!(find_result.is_none());
}

struct MockGroupRepository {
    group_store: Store<Group>,
    user_group_store: Store<UserGroup>,
}

impl MockGroupRepository {
    fn new(group_store: GroupStore, user_group_store: UserGroupStore) -> Self {
        Self {
            group_store,
            user_group_store,
        }
    }
}

#[async_trait]
impl keyrunes::repository::GroupRepository for MockGroupRepository {
    async fn find_by_name(
        &self,
        name: &str,
        _organization_id: i64,
        _namespace: &str,
    ) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().find(|g| g.name == name).cloned();
        Ok(group)
    }

    async fn find_by_id(&self, group_id: i64, _namespace: &str) -> Result<Option<Group>> {
        let groups = self.group_store.lock().unwrap();
        let group = groups.iter().find(|g| g.group_id == group_id).cloned();
        Ok(group)
    }

    async fn insert_group(
        &self,
        new_group: keyrunes::repository::NewGroup,
        _namespace: &str,
    ) -> Result<Group> {
        let mut groups = self.group_store.lock().unwrap();
        let group_id = groups.iter().map(|g| g.group_id).max().unwrap_or(0) + 1;
        let group = Group {
            group_id,
            external_id: new_group.external_id,
            organization_id: new_group.organization_id,
            name: new_group.name,
            description: new_group.description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        groups.push(group.clone());
        Ok(group)
    }

    async fn list_groups(&self, _organization_id: i64, _namespace: &str) -> Result<Vec<Group>> {
        Ok(self.group_store.lock().unwrap().clone())
    }

    async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
        _namespace: &str,
    ) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.push(UserGroup {
            user_id,
            group_id,
            assigned_by,
            assigned_at: Utc::now(),
        });
        Ok(())
    }

    async fn remove_user_from_group(
        &self,
        user_id: i64,
        group_id: i64,
        _namespace: &str,
    ) -> Result<()> {
        let mut user_groups = self.user_group_store.lock().unwrap();
        user_groups.retain(|g| !(g.user_id == user_id && g.group_id == group_id));
        Ok(())
    }

    async fn get_group_policies(&self, _group_id: i64, _namespace: &str) -> Result<Vec<Policy>> {
        Ok(Vec::new())
    }
}

struct MockSettingsRepository {
    settings_store: SettingsStore,
}

impl MockSettingsRepository {
    fn new() -> Self {
        Self {
            settings_store: Self::create_stores(),
        }
    }

    fn create_stores() -> SettingsStore {
        let settings_store: SettingsStore = Arc::new(Mutex::new(Vec::new()));

        settings_store.lock().unwrap().push(Settings {
            settings_id: 0,
            organization_id: Some(1),
            key: "test_key".to_string(),
            value: "test_value".to_string(),
            description: Some("Test settings".to_string()),
            created_at: Default::default(),
            updated_at: Default::default(),
        });

        settings_store.lock().unwrap().push(Settings {
            settings_id: 1,
            organization_id: Some(1),
            key: "test_key_1".to_string(),
            value: "test_value_1".to_string(),
            description: Some("Test settings 1".to_string()),
            created_at: Default::default(),
            updated_at: Default::default(),
        });

        settings_store
    }
}

#[async_trait]
impl keyrunes::repository::SettingsRepository for MockSettingsRepository {
    async fn create_settings(
        &self,
        settings: CreateSettings,
        _namespace: &str,
    ) -> Result<Option<CreateSettings>> {
        let settings_record = Settings {
            settings_id: 22,
            organization_id: Some(1),
            key: settings.key.clone(),
            value: settings.value.clone(),
            description: settings.description.clone(),
            created_at: Default::default(),
            updated_at: Default::default(),
        };

        self.settings_store.lock().unwrap().push(settings_record);

        Ok(Some(settings))
    }

    async fn get_settings_by_key(&self, key: &str, _namespace: &str) -> Result<Option<Settings>> {
        let res = self
            .settings_store
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.key == key)
            .cloned();

        Ok(res)
    }

    async fn get_setting_by_key_and_org(
        &self,
        key: &str,
        _organization_id: Option<i64>,
        namespace: &str,
    ) -> Result<Option<Settings>> {
        self.get_settings_by_key(key, namespace).await
    }

    async fn get_all_settings(&self, _namespace: &str) -> Result<Vec<Settings>> {
        let res = self
            .settings_store
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();

        Ok(res)
    }

    async fn update_settings_by_key(&self, key: &str, value: &str, _namespace: &str) -> Result<()> {
        if let Some(s) = self
            .settings_store
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.key == key)
        {
            s.value = value.to_string();
        }

        Ok(())
    }

    async fn delete_settings_by_key(&self, key: &str, _namespace: &str) -> Result<()> {
        self.settings_store.lock().unwrap().retain(|s| s.key != key);

        Ok(())
    }
}

struct MockPasswordResetRepository;

#[async_trait]
impl keyrunes::repository::PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(
        &self,
        _token: keyrunes::repository::NewPasswordResetToken,
        _namespace: &str,
    ) -> Result<keyrunes::repository::PasswordResetToken> {
        unimplemented!()
    }

    async fn find_valid_token(
        &self,
        _token: &str,
        _namespace: &str,
    ) -> Result<Option<keyrunes::repository::PasswordResetToken>> {
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
struct MockOrganizationRepository;

#[async_trait]
impl OrganizationRepository for MockOrganizationRepository {
    async fn find_by_name(&self, _name: &str) -> Result<Option<Organization>> {
        Ok(Some(OrganizationFactory::create_organization(
            keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            "Default".to_string(),
            DEFAULT_NAMESPACE.to_string(),
        )))
    }
    async fn find_by_id(&self, _organization_id: i64) -> Result<Option<Organization>> {
        Ok(Some(OrganizationFactory::create_organization(
            keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            "Default".to_string(),
            DEFAULT_NAMESPACE.to_string(),
        )))
    }
    async fn find_by_namespace(&self, namespace: &str) -> Result<Option<Organization>> {
        Ok(Some(OrganizationFactory::create_organization(
            keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            "Default".to_string(),
            namespace.to_string(),
        )))
    }
    async fn insert_organization(&self, _new_org: NewOrganization) -> Result<Organization> {
        unimplemented!()
    }
    async fn list_organizations(&self) -> Result<Vec<Organization>> {
        Ok(Vec::new())
    }
    async fn find_by_secret_key(&self, _secret_key: Uuid) -> Result<Option<Organization>> {
        Ok(None)
    }
    async fn rotate_secret_key(&self, _organization_id: i64) -> Result<Uuid> {
        Ok(Uuid::new_v4())
    }
    async fn delete_organization(&self, _organization_id: i64) -> Result<()> {
        Ok(())
    }
}

fn helper_service() -> UserServiceType {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));

    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    UserService::new(
        user_repo,
        group_repo,
        Arc::new(MockOrganizationRepository),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    )
}

#[tokio::test]
async fn test_settings_functionality() {
    // Setup
    let service = helper_service();
    let test_key = String::from("settings test key");
    let test_value = String::from("settings test value");
    let test_value_update = String::from("settings test value updated");
    let test_description = String::from("settings test description");

    // Act
    let settings_inserted = service
        .settings_service
        .insert_settings(
            test_key.clone(),
            test_value.clone(),
            test_description.clone(),
            DEFAULT_NAMESPACE,
        )
        .await;

    // Assert
    assert!(settings_inserted.is_ok());

    let result_settings = service
        .settings_service
        .find_settings_by_key(test_key.as_str(), DEFAULT_NAMESPACE)
        .await;

    assert!(result_settings.is_ok());

    let result_settings = result_settings.unwrap();
    assert!(result_settings.key == test_key);
    assert!(result_settings.value == test_value.clone());
    assert!(result_settings.description.unwrap() == test_description);

    // Act
    let result = service
        .settings_service
        .update_settings(
            test_key.clone(),
            test_value_update.clone(),
            DEFAULT_NAMESPACE,
        )
        .await;

    // Assert
    assert!(result.is_ok());

    let updated_result_settings = service
        .settings_service
        .find_settings_by_key(test_key.as_str(), DEFAULT_NAMESPACE)
        .await;
    assert!(updated_result_settings.is_ok());

    let updated_result_settings = updated_result_settings.unwrap();

    assert!(updated_result_settings.key == test_key);
    assert!(updated_result_settings.value == test_value_update);

    // Act
    let settings_deleted = service
        .settings_service
        .delete_settings(test_key.clone(), DEFAULT_NAMESPACE)
        .await;

    // Assert
    assert!(settings_deleted.is_ok());

    let result_find_deleted = service
        .settings_service
        .find_settings_by_key(test_key.as_str(), DEFAULT_NAMESPACE)
        .await;
    assert!(result_find_deleted.is_err());
}

#[tokio::test]
async fn test_register_and_login() {
    // Setup
    let service = helper_service();
    let user_data = UserFactory::build();

    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
        group: None,
    };

    // Act
    let auth_response = service
        .register(req.clone(), DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    assert_eq!(auth_response.user.email, user_data.email);
    assert_eq!(auth_response.user.username, user_data.username);
    assert!(!auth_response.token.is_empty());

    // Act
    let login_response = service
        .login(
            user_data.email.clone(),
            "Password123".to_string(),
            DEFAULT_NAMESPACE,
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(login_response.user.username, user_data.username);
    assert!(!login_response.token.is_empty());

    // Act
    let login_response2 = service
        .login(
            user_data.username.clone(),
            "Password123".to_string(),
            DEFAULT_NAMESPACE,
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(login_response2.user.email, user_data.email);

    // Act
    let err = service
        .login(
            user_data.username.clone(),
            "wrongpass".to_string(),
            DEFAULT_NAMESPACE,
        )
        .await
        .unwrap_err();

    // Assert
    assert_eq!(err.to_string(), "invalid credentials");
}

#[tokio::test]
async fn test_duplicate_registration() {
    // Setup
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo.clone(),
        group_repo,
        Arc::new(MockOrganizationRepository),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    let user_data = UserFactory::build();
    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
        group: None,
    };

    // Act
    service
        .register(req.clone(), DEFAULT_NAMESPACE)
        .await
        .unwrap();
    let result = service.register(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("email already registered")
    );
}

#[tokio::test]
async fn test_password_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo,
        group_repo,
        Arc::new(MockOrganizationRepository),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    // Setup
    let req = RegisterRequest {
        email: "short@example.com".to_string(),
        username: "shortpass".to_string(),
        password: "short".to_string(),
        first_login: Some(false),
        organization_id: None,
        group: None,
    };

    // Act
    let result = service.register(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "password too short");
}

#[tokio::test]
async fn test_email_validation() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));
    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let service = UserService::new(
        user_repo,
        group_repo,
        Arc::new(MockOrganizationRepository),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    // Setup
    let req = RegisterRequest {
        email: "invalid-email".to_string(),
        username: "testuser".to_string(),
        password: "Password123".to_string(),
        first_login: Some(false),
        organization_id: None,
        group: None,
    };

    // Act
    let result = service.register(req, DEFAULT_NAMESPACE).await;

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "invalid email");
}

#[tokio::test]
async fn test_change_password() {
    // Setup
    let service = helper_service();
    let user_data = UserFactory::build();

    let req = RegisterRequest {
        email: user_data.email.clone(),
        username: user_data.username.clone(),
        password: "OldPassword123".to_string(),
        first_login: Some(true),
        organization_id: None,
        group: None,
    };

    let auth_response = service.register(req, DEFAULT_NAMESPACE).await.unwrap();
    let user_id = auth_response.user.user_id;

    // Act
    let change_req = keyrunes::services::user_service::ChangePasswordRequest {
        current_password: "OldPassword123".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    service
        .change_password(user_id, change_req, DEFAULT_NAMESPACE)
        .await
        .unwrap();

    // Assert
    let login_result = service
        .login(
            user_data.email.clone(),
            "NewPassword456".to_string(),
            DEFAULT_NAMESPACE,
        )
        .await;
    assert!(login_result.is_ok());

    // Act
    let old_login_result = service
        .login(
            user_data.email.clone(),
            "OldPassword123".to_string(),
            DEFAULT_NAMESPACE,
        )
        .await;

    // Assert
    assert!(old_login_result.is_err());
}

#[tokio::test]
async fn admin_create_user_with_groups() {
    let (group_store, user_groups_store) = create_stores();
    let user_repo = Arc::new(MockRepo::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let password_reset_repo = Arc::new(MockPasswordResetRepository);
    let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
        "0123456789ABCDEF0123456789ABCDEF",
    ));

    let settings_repo = Arc::new(MockSettingsRepository::new());
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let group_repo = Arc::new(MockGroupRepository::new(
        Arc::clone(&group_store),
        Arc::clone(&user_groups_store),
    ));
    let service = UserService::new(
        user_repo,
        group_repo.clone(),
        Arc::new(MockOrganizationRepository),
        password_reset_repo,
        jwt_service,
        settings_service,
        None,
    );

    let group_service = GroupService::new(group_repo.clone());

    // Setup
    let superadmin = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("admin@example.com").unwrap(),
                username: "admin".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec![keyrunes::constants::SUPERADMIN_GROUP.to_string()]),
                first_login: false,
                organization_id: keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            },
            None,
            DEFAULT_NAMESPACE,
        )
        .await
        .unwrap();

    // Act
    let test_group = group_service
        .create_group(
            CreateGroupRequest {
                organization_id: keyrunes::constants::DEFAULT_ORGANIZATION_ID,
                name: "test".to_string(),
                description: Some("Test Group".to_string()),
            },
            DEFAULT_NAMESPACE,
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(group_store.lock().unwrap().len(), 5);

    // Act
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser@example.com").unwrap(),
                username: "testuser".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec![
                    keyrunes::constants::USERS_GROUP.to_string(),
                    test_group.name.clone(),
                ]),
                first_login: false,
                organization_id: keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            },
            Some(superadmin.user_id),
            DEFAULT_NAMESPACE,
        )
        .await;

    // Assert
    assert!(test_user.is_ok());
    let test_user = test_user.unwrap();
    assert_eq!(test_user.email, "testuser@example.com");
    assert_eq!(test_user.username, "testuser");
    assert_eq!(
        test_user.groups,
        vec![
            keyrunes::constants::USERS_GROUP.to_string(),
            test_group.name
        ]
    );

    // Act
    let test_user = service
        .create_user(
            CreateUserRequest {
                email: Email::try_from("testuser2@example.com").unwrap(),
                username: "testuser2".to_string(),
                password: Password::try_from("Password123").unwrap(),
                groups: Some(vec![
                    keyrunes::constants::USERS_GROUP.to_string(),
                    "invalid".to_string(),
                ]),
                first_login: false,
                organization_id: keyrunes::constants::DEFAULT_ORGANIZATION_ID,
            },
            Some(superadmin.user_id),
            DEFAULT_NAMESPACE,
        )
        .await;

    // Assert
    assert!(test_user.is_err());
    assert_eq!(
        test_user.err().unwrap().to_string(),
        "invalid group specified: `invalid`"
    )
}

#[tokio::test]
async fn test_register_first_user_in_namespace() {
    // Setup
    let service = helper_service();

    // Act - Register first user in public namespace
    let reg1 = RegisterRequest {
        email: "first_public@example.com".to_string(),
        username: "first_public".to_string(),
        password: "Password123".to_string(),
        first_login: None,
        organization_id: Some(1),
        group: None,
    };
    let res1 = service.register(reg1, DEFAULT_NAMESPACE).await.unwrap();

    // Assert - Should have superadmin and users groups
    assert!(res1.user.groups.contains(&"superadmin".to_string()));
    assert!(res1.user.groups.contains(&"users".to_string()));

    // Act - Register first user in a different namespace/org
    let reg2 = RegisterRequest {
        email: "first_org@example.com".to_string(),
        username: "first_org".to_string(),
        password: "Password123".to_string(),
        first_login: None,
        organization_id: Some(2),
        group: None,
    };
    let res2 = service.register(reg2, "org_2").await.unwrap();

    // Assert - Should have admin and users groups
    assert!(res2.user.groups.contains(&"admin".to_string()));
    assert!(res2.user.groups.contains(&"users".to_string()));
    assert!(!res2.user.groups.contains(&"superadmin".to_string()));
}
