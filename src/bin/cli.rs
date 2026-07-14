use clap::{Parser, Subcommand};
use keyrunes::NewPasswordResetToken;
use keyrunes::OrganizationRepository;
use keyrunes::PasswordResetRepository;
use keyrunes::UserRepository;
use keyrunes::constants::{DEFAULT_NAMESPACE, SUPERADMIN_GROUP};
use keyrunes::jwt_service::JwtService;
use keyrunes::repository::sqlx_impl::PgUserRepository;
use keyrunes::services::email_service::EmailService;
use keyrunes::services::group_service::{CreateGroupRequest, GroupService};
use keyrunes::services::organization_service::{CreateOrganizationRequest, OrganizationService};
use keyrunes::services::user_service::{RegisterRequest, UserService};
use keyrunes::sqlx_impl::{
    PgGroupRepository, PgOrganizationRepository, PgPasswordResetRepository, PgSettingsRepository,
};
use keyrunes::user_service::{AdminChangePasswordRequest, SettingsService};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tera::Tera;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser)]
#[clap(name = "Keyrunes CLI")]
#[clap(version)]
#[clap(about = "Use keyrunes via cli as sysadmin, or developer")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register User with username, password and email
    Register {
        #[clap(long)]
        organization_id: Option<i64>,
        #[clap(long)]
        email: String,
        #[clap(long)]
        username: String,
        #[clap(long)]
        password: String,
        #[clap(long)]
        first_login: bool,
        #[clap(long, default_value = "public")]
        namespace: String,
        #[clap(long)]
        group: Option<String>,
    },
    /// Create first superadmin user
    CreateSuperadmin {
        #[clap(long)]
        email: String,
        #[clap(long)]
        username: String,
        #[clap(long)]
        password: String,
    },
    /// Login as a user with username, password
    Login {
        #[clap(long)]
        identity: String,
        #[clap(long)]
        password: String,
    },
    /// recover user by generating token
    RecoverUser {
        #[clap(long)]
        username: String,
        #[clap(long)]
        generate_token: bool,
    },
    /// set user password
    SetUserPassword {
        #[clap(long)]
        email: String,

        #[clap(long)]
        set_password: bool,

        #[clap(long)]
        password: String,
    },
    /// Create a new group
    CreateGroup {
        #[clap(long, default_value = "public")]
        namespace: String,
        #[clap(long)]
        name: String,
        #[clap(long)]
        description: Option<String>,
    },
    /// Create a new organization
    CreateOrganization {
        #[clap(long)]
        name: String,
        #[clap(long)]
        description: Option<String>,
    },
    /// List all organizations
    ListOrganizations,
    /// List all groups in a namespace
    ListGroups {
        #[clap(long, default_value = "public")]
        namespace: String,
    },
    /// List all users in a namespace with their groups
    ListUsers {
        #[clap(long, default_value = "public")]
        namespace: String,
    },
    /// Assign user to group
    AssignUserToGroup {
        #[clap(long)]
        username: String,
        #[clap(long)]
        group_name: String,
        #[clap(long, default_value = "public")]
        namespace: String,
    },
    /// Remove user from group
    RemoveUserFromGroup {
        #[clap(long)]
        username: String,
        #[clap(long)]
        group_name: String,
        #[clap(long, default_value = "public")]
        namespace: String,
    },
    /// Rotate organization secret key
    RotateOrgKey {
        #[clap(long)]
        namespace: String,
    },
    /// Run database migrations
    Migrate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/keyrunes".into());

    let pool = PgPool::connect(&database_url).await?;

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let org_repo = Arc::new(PgOrganizationRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));

    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".into());

    let _tera = Arc::new(Tera::new("templates/**/*").expect("Failed to load templates"));

    let jwt_service = Arc::new(JwtService::new(&jwt_secret));
    let settings_repo = Arc::new(PgSettingsRepository::new(pool.clone()));
    let settings_service = Arc::new(SettingsService::new(settings_repo));

    let email_service = EmailService::from_env(_tera.clone()).ok().map(Arc::new);

    let service = Arc::new(UserService::new(
        user_repo,
        Arc::clone(&group_repo),
        org_repo.clone(),
        password_reset_repo.clone(),
        jwt_service.clone(),
        settings_service,
        email_service.clone(),
    ));

    match cli.command {
        Commands::Register {
            organization_id,
            email,
            username,
            password,
            first_login,
            namespace,
            group,
        } => {
            let req = RegisterRequest {
                organization_id,
                email,
                username,
                password,
                first_login: Some(first_login),
                group,
            };
            match service.register(req, &namespace).await {
                Ok(u) => println!(
                    "Created user {} (external_id={}) in namespace '{}'",
                    u.user.user_id, u.user.external_id, namespace
                ),
                Err(e) => eprintln!("Error registering user: {}", e),
            }
        }
        Commands::CreateSuperadmin {
            email,
            username,
            password,
        } => {
            let req = RegisterRequest {
                organization_id: Some(1),
                email: email.clone(),
                username: username.clone(),
                password,
                first_login: Some(false),
                group: None,
            };

            match service.register(req, DEFAULT_NAMESPACE).await {
                Ok(u) => {
                    tracing::info!("Created user {} (id={})", u.user.username, u.user.user_id);

                    tracing::info!("   User ID: {}", u.user.user_id);
                    tracing::info!("   Group: superadmin");

                    let group_service = GroupService::new(group_repo.clone());
                    match group_service
                        .get_group_by_name(SUPERADMIN_GROUP, 1, DEFAULT_NAMESPACE)
                        .await
                    {
                        Ok(Some(group)) => {
                            match group_service
                                .assign_user_to_group(
                                    u.user.user_id,
                                    group.group_id,
                                    None,
                                    DEFAULT_NAMESPACE,
                                )
                                .await
                            {
                                Ok(_) => {
                                    tracing::info!("✅ Superadmin user created successfully!");
                                    tracing::info!("   Email: {}", email);
                                    tracing::info!("   Username: {}", username);
                                    tracing::info!("   User ID: {}", u.user.user_id);
                                    tracing::info!("   Group: superadmin");
                                }
                                Err(e) => {
                                    eprintln!("Error assigning user to superadmin group: {}", e)
                                }
                            }
                        }
                        Ok(None) => {
                            eprintln!("Error: superadmin group not found. Run migrations first.")
                        }
                        Err(e) => eprintln!("Error finding superadmin group: {}", e),
                    }
                }
                Err(e) => eprintln!("Error creating user: {}", e),
            }
        }
        Commands::Login { identity, password } => {
            match service.login(identity, password, DEFAULT_NAMESPACE).await {
                Ok(u) => println!("Login successful! Welcome {}", u.user.username),
                Err(e) => eprintln!("Login failed: {}", e),
            }
        }
        Commands::RecoverUser {
            username,
            generate_token: _,
        } => {
            let res = service
                .find_user_by_username(&username, DEFAULT_NAMESPACE)
                .await;

            if res.is_none() {
                return Err(anyhow::anyhow!("User {} not found", username));
            }

            let user = res.unwrap();

            let user_group = service
                .get_user_group_names(user.user_id, DEFAULT_NAMESPACE)
                .await?;

            let jwt_generated_token = jwt_service
                .generate_token(
                    user.user_id,
                    user.username.as_str(),
                    user.email.as_str(),
                    user_group,
                    DEFAULT_NAMESPACE,
                    user.organization_id,
                )
                .map_err(|err| tracing::error!("Error generating token: {}", err));

            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(3600);

            let new_password_token = NewPasswordResetToken {
                user_id: user.user_id,
                token: jwt_generated_token.unwrap(),
                expires_at,
            };

            let password_reset_token = service
                .password_reset_repo
                .create_reset_token(new_password_token, DEFAULT_NAMESPACE)
                .await?;

            let base_url_settings: HashMap<String, String> = HashMap::from_iter(
                &mut service
                    .settings_service
                    .get_all_settings(DEFAULT_NAMESPACE)
                    .await?
                    .iter()
                    .map(|setting| (setting.key.clone(), setting.value.clone())),
            );

            let default_url = "http://localhost:3000".to_string();
            let base_url = base_url_settings.get("BASE_URL").unwrap_or(&default_url);

            tracing::info!("Generated reset url for user {} below", username);
            tracing::info!(
                "reset url {}?token={}",
                base_url,
                password_reset_token.token
            );

            if let Some(email_svc) = email_service {
                match email_svc
                    .send_password_reset_email(&user.email, &password_reset_token.token)
                    .await
                {
                    Ok(_) => tracing::info!("Recovery email sent to {}", user.email),
                    Err(e) => eprintln!("Error sending email: {}", e),
                }
            }
        }
        Commands::SetUserPassword {
            email,
            set_password: _set_password,
            password,
        } => {
            let user = service.find_user_by_email(&email, DEFAULT_NAMESPACE).await;

            if user.is_none() {
                return Err(anyhow::anyhow!("User with email {} not found", email));
            }

            let user = user.unwrap();
            let change_password_request = AdminChangePasswordRequest {
                user_id: user.user_id,
                new_password: password.to_string(),
            };

            service
                .update_password(change_password_request, DEFAULT_NAMESPACE)
                .await?;

            tracing::info!("Updated password successfully for {}", user.username);
        }
        Commands::CreateGroup {
            namespace,
            name,
            description,
        } => {
            let org_service = OrganizationService::new(org_repo.clone(), group_repo.clone());
            match org_service.list_organizations().await {
                Ok(orgs) => {
                    if let Some(org) = orgs.iter().find(|o| o.namespace == namespace) {
                        let group_service = GroupService::new(group_repo.clone());
                        let req = CreateGroupRequest {
                            organization_id: org.organization_id,
                            name: name.clone(),
                            description,
                        };

                        match group_service.create_group(req, &namespace).await {
                            Ok(group) => {
                                tracing::info!(
                                    "✅ Group created successfully in namespace '{}'!",
                                    namespace
                                );
                                tracing::info!("   Name: {}", group.name);
                                tracing::info!("   Group ID: {}", group.group_id);
                                tracing::info!("   External ID: {}", group.external_id);
                            }
                            Err(e) => eprintln!("Error creating group: {}", e),
                        }
                    } else {
                        eprintln!(
                            "Error: No organization found with namespace '{}'",
                            namespace
                        );
                    }
                }
                Err(e) => eprintln!("Error finding organization: {}", e),
            }
        }
        Commands::ListGroups { namespace } => {
            let org_service = OrganizationService::new(org_repo.clone(), group_repo.clone());
            match org_service.list_organizations().await {
                Ok(orgs) => {
                    if let Some(org) = orgs.iter().find(|o| o.namespace == namespace) {
                        let group_service = GroupService::new(group_repo.clone());
                        match group_service
                            .list_groups(org.organization_id, &namespace)
                            .await
                        {
                            Ok(groups) => {
                                tracing::info!("📋 Groups in namespace '{}':", namespace);
                                for group in groups {
                                    tracing::info!(
                                        "  • {} (ID: {}) - {}",
                                        group.name,
                                        group.group_id,
                                        group
                                            .description
                                            .unwrap_or_else(|| "No description".to_string())
                                    );
                                }
                            }
                            Err(e) => eprintln!("Error listing groups: {}", e),
                        }
                    } else {
                        eprintln!(
                            "Error: No organization found with namespace '{}'",
                            namespace
                        );
                    }
                }
                Err(e) => eprintln!("Error finding organization: {}", e),
            }
        }
        Commands::ListUsers { namespace } => match org_repo.list_organizations().await {
            Ok(orgs) => {
                if let Some(org) = orgs.iter().find(|o| o.namespace == namespace) {
                    tracing::info!(
                        "👥 Users in namespace '{}' (Organization: {}):",
                        namespace,
                        org.name
                    );
                    tracing::info!(
                        "Note: Full user listing requires database query. Use admin panel or direct SQL query."
                    );
                    tracing::info!(
                        "Suggested query: SELECT u.username, u.email, array_agg(g.name) as groups FROM users u LEFT JOIN user_groups ug ON u.user_id = ug.user_id LEFT JOIN groups g ON ug.group_id = g.group_id WHERE u.organization_id = {} GROUP BY u.user_id, u.username, u.email;",
                        org.organization_id
                    );
                } else {
                    eprintln!(
                        "Error: No organization found with namespace '{}'",
                        namespace
                    );
                }
            }
            Err(e) => eprintln!("Error finding organization: {}", e),
        },
        Commands::AssignUserToGroup {
            username,
            group_name,
            namespace,
        } => {
            match service
                .user_repo
                .find_by_username(&username, &namespace)
                .await
            {
                Ok(Some(user)) => {
                    let organization_id = user.organization_id;
                    let group_service = GroupService::new(group_repo.clone());

                    match group_service
                        .get_group_by_name(&group_name, organization_id, &namespace)
                        .await
                    {
                        Ok(Some(group)) => {
                            match group_service
                                .assign_user_to_group(
                                    user.user_id,
                                    group.group_id,
                                    None,
                                    &namespace,
                                )
                                .await
                            {
                                Ok(_) => {
                                    tracing::info!(
                                        "User '{}' assigned to group '{}' in namespace '{}' successfully!",
                                        username,
                                        group_name,
                                        namespace
                                    );
                                }
                                Err(e) => eprintln!("Error assigning user to group: {}", e),
                            }
                        }
                        Ok(None) => eprintln!(
                            "Error: Group '{}' not found in namespace '{}'",
                            group_name, namespace
                        ),
                        Err(e) => eprintln!("Error finding group: {}", e),
                    }
                }
                Ok(None) => eprintln!(
                    "Error: User '{}' not found in namespace '{}'",
                    username, namespace
                ),
                Err(e) => eprintln!("Error finding user: {}", e),
            }
        }
        Commands::RemoveUserFromGroup {
            username,
            group_name,
            namespace,
        } => {
            match service
                .user_repo
                .find_by_username(&username, &namespace)
                .await
            {
                Ok(Some(user)) => {
                    let organization_id = user.organization_id;
                    let group_service = GroupService::new(group_repo.clone());

                    match group_service
                        .get_group_by_name(&group_name, organization_id, &namespace)
                        .await
                    {
                        Ok(Some(group)) => {
                            match group_service
                                .remove_user_from_group(user.user_id, group.group_id, &namespace)
                                .await
                            {
                                Ok(_) => {
                                    tracing::info!(
                                        "User '{}' removed from group '{}' in namespace '{}' successfully!",
                                        username,
                                        group_name,
                                        namespace
                                    );
                                }
                                Err(e) => eprintln!("Error removing user from group: {}", e),
                            }
                        }
                        Ok(None) => eprintln!(
                            "Error: Group '{}' not found in namespace '{}'",
                            group_name, namespace
                        ),
                        Err(e) => eprintln!("Error finding group: {}", e),
                    }
                }
                Ok(None) => eprintln!(
                    "Error: User '{}' not found in namespace '{}'",
                    username, namespace
                ),
                Err(e) => eprintln!("Error finding user: {}", e),
            }
        }
        Commands::CreateOrganization { name, description } => {
            let org_service = OrganizationService::new(org_repo.clone(), group_repo.clone());
            let req = CreateOrganizationRequest {
                name: name.clone(),
                description: description.clone(),
                namespace: name.to_lowercase().replace(' ', "_"),
                base_url: None,
            };

            match org_service.create_organization(req).await {
                Ok(org) => {
                    tracing::info!("✅ Organization created successfully!");
                    tracing::info!("   Name: {}", org.name);
                    tracing::info!("   ID: {}", org.organization_id);
                    tracing::info!("   External ID: {}", org.external_id);
                    tracing::info!("   Secret Key: {}", org.secret_key);
                }
                Err(e) => eprintln!("Error creating organization: {}", e),
            }
        }
        Commands::ListOrganizations => {
            let org_service = OrganizationService::new(org_repo.clone(), group_repo.clone());
            match org_service.list_organizations().await {
                Ok(orgs) => {
                    tracing::info!("📋 Organizations:");
                    for org in orgs {
                        tracing::info!(
                            "  • {} (ID: {}, Namespace: {}) - {}",
                            org.name,
                            org.organization_id,
                            org.namespace,
                            org.description
                                .unwrap_or_else(|| "No description".to_string())
                        );
                    }
                }
                Err(e) => eprintln!("Error listing organizations: {}", e),
            }
        }
        Commands::RotateOrgKey { namespace } => {
            let org_service = OrganizationService::new(org_repo.clone(), group_repo.clone());
            match org_service.list_organizations().await {
                Ok(orgs) => {
                    if let Some(org) = orgs.iter().find(|o| o.namespace == namespace) {
                        match org_service.rotate_org_key(org.organization_id).await {
                            Ok(new_key) => {
                                tracing::info!("✅ Organization key rotated successfully!");
                                tracing::info!(
                                    "   Organization: {} (Namespace: {})",
                                    org.name,
                                    namespace
                                );
                                tracing::info!("   New Secret Key: {}", new_key);
                            }
                            Err(e) => eprintln!("Error rotating organization key: {}", e),
                        }
                    } else {
                        eprintln!(
                            "Error: No organization found with namespace '{}'",
                            namespace
                        );
                    }
                }
                Err(e) => eprintln!("Error finding organization: {}", e),
            }
        }
        Commands::Migrate => {
            tracing::info!("🏃 Running migrations...");
            match sqlx::migrate!("./migrations").run(&pool).await {
                Ok(_) => tracing::info!("✅ Migrations completed successfully!"),
                Err(e) => {
                    eprintln!("❌ Migration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrunes::repository::{
        CreateSettings, Group, NewOrganization, NewPasswordResetToken, Organization,
        OrganizationRepository, PasswordResetRepository, PasswordResetToken, Settings,
        SettingsRepository, User, UserRepository,
    };
    use keyrunes::services::user_service::{SettingsService, UserService};
    use serial_test::serial;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    type Store<T> = Arc<Mutex<Vec<T>>>;
    type UserStore = Store<User>;

    async fn setup_cli_test_db() {
        dotenvy::dotenv().ok();
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            std::env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:password@localhost:5432/keyrunes".to_string())
        });
        let pool = PgPool::connect(&db_url)
            .await
            .expect("Failed to connect to DB");

        sqlx::migrate!()
            .run(&pool)
            .await
            .expect("Failed to migrate");

        sqlx::query("TRUNCATE TABLE organizations, users, groups, user_groups, settings, password_reset_tokens CASCADE")
            .execute(&pool)
            .await
            .expect("Failed to truncate tables");

        sqlx::query("INSERT INTO organizations (organization_id, name, external_id, secret_key, description, namespace, base_url, created_at, updated_at) VALUES (1, 'Default Org', $1, $2, 'Default', 'public', NULL, NOW(), NOW()) ON CONFLICT (organization_id) DO NOTHING")
             .bind(Uuid::new_v4())
             .bind(Uuid::new_v4())
             .execute(&pool).await.expect("Failed to seed org");

        sqlx::query("INSERT INTO groups (group_id, organization_id, name, description, external_id, created_at, updated_at) VALUES (1, 1, 'superadmin', 'Super Admin', $1, NOW(), NOW()) ON CONFLICT (group_id) DO NOTHING")
             .bind(Uuid::new_v4())
             .execute(&pool).await.expect("Failed to seed group");

        sqlx::query("INSERT INTO users (user_id, organization_id, email, username, password_hash, first_login, external_id, created_at, updated_at) VALUES (1, 1, 'admin@example.com', 'admin', '$argon2id$v=19$m=19456,t=2,p=1$dummy$dummyhash', false, $1, NOW(), NOW()) ON CONFLICT (user_id) DO NOTHING")
             .bind(Uuid::new_v4())
             .execute(&pool).await.expect("Failed to seed user");

        sqlx::query("INSERT INTO user_groups (user_id, group_id, assigned_at) VALUES (1, 1, NOW()) ON CONFLICT (user_id, group_id) DO NOTHING")
             .execute(&pool).await.expect("Failed to assign group");
    }

    const USERNAME: &str = "admin";
    const EMAIL: &str = "admin@example.com";
    const PASSWORD: &str = "Admin123";

    struct MockUserRepo {
        users: UserStore,
    }

    impl MockUserRepo {
        fn new() -> Self {
            let users = Arc::new(Mutex::new(Vec::new()));
            users.lock().unwrap().push(User {
                user_id: 1,
                external_id: Uuid::new_v4(),
                organization_id: 1,
                email: EMAIL.to_string(),
                username: USERNAME.to_string(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$test$test".to_string(),
                first_login: false,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
            Self { users }
        }
    }

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepo {
        async fn insert_user(
            &self,
            _user: keyrunes::NewUser,
            _namespace: &str,
        ) -> anyhow::Result<User> {
            unimplemented!()
        }
        async fn find_by_email(
            &self,
            email: &str,
            _namespace: &str,
        ) -> anyhow::Result<Option<User>> {
            Ok(self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.email == email)
                .cloned())
        }
        async fn find_by_username(
            &self,
            username: &str,
            _namespace: &str,
        ) -> anyhow::Result<Option<User>> {
            Ok(self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.username == username)
                .cloned())
        }
        async fn find_by_id(&self, _id: i64, _namespace: &str) -> anyhow::Result<Option<User>> {
            unimplemented!()
        }
        async fn update_user_password(
            &self,
            user_id: i64,
            password_hash: &str,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.password_hash = password_hash.to_string();
            }
            Ok(())
        }
        async fn update_user_profile(
            &self,
            user_id: i64,
            email: &str,
            username: &str,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.iter_mut().find(|u| u.user_id == user_id) {
                user.email = email.to_string();
                user.username = username.to_string();
            }
            Ok(())
        }
        async fn set_first_login(
            &self,
            _user_id: i64,
            _first_login: bool,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn get_user_groups(
            &self,
            _user_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Vec<Group>> {
            Ok(vec![])
        }
        async fn get_user_policies(
            &self,
            _user_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }
        async fn get_user_all_policies(
            &self,
            _user_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }

        async fn count_users(&self, _namespace: &str) -> anyhow::Result<i64> {
            Ok(0)
        }

        async fn delete_user(&self, _user_id: i64, _namespace: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockGroupRepo;

    #[async_trait::async_trait]
    impl keyrunes::repository::GroupRepository for MockGroupRepo {
        async fn insert_group(
            &self,
            _group: keyrunes::NewGroup,
            _namespace: &str,
        ) -> anyhow::Result<Group> {
            unimplemented!()
        }
        async fn find_by_name(
            &self,
            _name: &str,
            _organization_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Option<Group>> {
            Ok(None)
        }
        async fn find_by_id(&self, _id: i64, _namespace: &str) -> anyhow::Result<Option<Group>> {
            unimplemented!()
        }
        async fn list_groups(
            &self,
            _organization_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Vec<Group>> {
            Ok(vec![])
        }
        async fn assign_user_to_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn remove_user_from_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_group_policies(
            &self,
            _group_id: i64,
            _namespace: &str,
        ) -> anyhow::Result<Vec<keyrunes::repository::Policy>> {
            Ok(vec![])
        }
    }

    struct MockPasswordResetRepo;

    #[async_trait::async_trait]
    impl PasswordResetRepository for MockPasswordResetRepo {
        async fn create_reset_token(
            &self,
            token: NewPasswordResetToken,
            _namespace: &str,
        ) -> anyhow::Result<PasswordResetToken> {
            Ok(PasswordResetToken {
                token_id: 1,
                user_id: token.user_id,
                token: token.token,
                expires_at: token.expires_at,
                used_at: None,
                created_at: chrono::Utc::now(),
            })
        }
        async fn find_valid_token(
            &self,
            _token: &str,
            _namespace: &str,
        ) -> anyhow::Result<Option<PasswordResetToken>> {
            Ok(None)
        }
        async fn mark_token_used(&self, _token_id: i64, _namespace: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn cleanup_expired_tokens(&self, _namespace: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockSettingsRepo;

    #[async_trait::async_trait]
    impl SettingsRepository for MockSettingsRepo {
        async fn create_settings(
            &self,
            _settings: CreateSettings,
            _namespace: &str,
        ) -> anyhow::Result<Option<CreateSettings>> {
            Ok(None)
        }
        async fn get_settings_by_key(
            &self,
            key: &str,
            _namespace: &str,
        ) -> anyhow::Result<Option<Settings>> {
            if key == "BASE_URL" {
                Ok(Some(Settings {
                    settings_id: 1,
                    organization_id: Some(1),
                    key: "BASE_URL".to_string(),
                    value: "http://localhost:3000".to_string(),
                    description: Some("Base URL".to_string()),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }
        async fn get_setting_by_key_and_org(
            &self,
            key: &str,
            _organization_id: Option<i64>,
            _namespace: &str,
        ) -> anyhow::Result<Option<Settings>> {
            self.get_settings_by_key(key, DEFAULT_NAMESPACE).await
        }
        async fn get_all_settings(&self, _namespace: &str) -> anyhow::Result<Vec<Settings>> {
            Ok(vec![Settings {
                settings_id: 1,
                organization_id: Some(1),
                key: "BASE_URL".to_string(),
                value: "http://localhost:3000".to_string(),
                description: Some("Base URL".to_string()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }])
        }
        async fn update_settings_by_key(
            &self,
            _key: &str,
            _value: &str,
            _namespace: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete_settings_by_key(&self, _key: &str, _namespace: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockOrganizationRepo;

    #[async_trait::async_trait]
    impl OrganizationRepository for MockOrganizationRepo {
        async fn find_by_name(&self, _name: &str) -> anyhow::Result<Option<Organization>> {
            Ok(Some(Organization {
                organization_id: 1,
                external_id: Uuid::new_v4(),
                name: "Default".to_string(),
                secret_key: Uuid::new_v4(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                description: None,
                base_url: None,
                namespace: DEFAULT_NAMESPACE.to_string(),
            }))
        }
        async fn find_by_id(&self, _organization_id: i64) -> anyhow::Result<Option<Organization>> {
            Ok(None)
        }
        async fn find_by_namespace(&self, namespace: &str) -> anyhow::Result<Option<Organization>> {
            Ok(Some(Organization {
                organization_id: 1,
                external_id: Uuid::new_v4(),
                name: "Default".to_string(),
                secret_key: Uuid::new_v4(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                description: None,
                base_url: None,
                namespace: namespace.to_string(),
            }))
        }
        async fn insert_organization(
            &self,
            _new_org: NewOrganization,
        ) -> anyhow::Result<Organization> {
            unimplemented!()
        }
        async fn list_organizations(&self) -> anyhow::Result<Vec<Organization>> {
            Ok(Vec::new())
        }
        async fn find_by_secret_key(
            &self,
            _secret_key: Uuid,
        ) -> anyhow::Result<Option<Organization>> {
            Ok(None)
        }
        async fn rotate_secret_key(&self, _organization_id: i64) -> anyhow::Result<Uuid> {
            Ok(Uuid::new_v4())
        }
        async fn delete_organization(&self, _organization_id: i64) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_update_password_with_valid_email() {
        // Setup
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
            "test_secret",
        ));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let _org_repo = Arc::new(MockOrganizationRepo);

        let service = UserService::new(
            user_repo.clone(),
            group_repo,
            Arc::new(MockOrganizationRepo),
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Act
        let user = service.find_user_by_email(EMAIL, DEFAULT_NAMESPACE).await;

        // Assert
        assert!(user.is_some());

        // Act
        let user = user.unwrap();
        let request = AdminChangePasswordRequest {
            user_id: user.user_id,
            new_password: "NewPassword123".to_string(),
        };

        let result = service.update_password(request, DEFAULT_NAMESPACE).await;

        // Assert
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_password_with_invalid_email() {
        // Setup
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
            "test_secret",
        ));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let _org_repo = Arc::new(MockOrganizationRepo);

        let service = UserService::new(
            user_repo,
            group_repo,
            Arc::new(MockOrganizationRepo),
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Act
        let user = service
            .find_user_by_email("nonexistent@example.com", DEFAULT_NAMESPACE)
            .await;

        // Assert
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_recover_user_with_valid_username() {
        // Setup
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
            "0123456789ABCDEF0123456789ABCDEF",
        ));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let _org_repo = Arc::new(MockOrganizationRepo);

        let service = UserService::new(
            user_repo,
            group_repo,
            Arc::new(MockOrganizationRepo),
            password_reset_repo,
            jwt_service.clone(),
            settings_service.clone(),
            None,
        );

        // Act
        let user = service
            .find_user_by_username(USERNAME, DEFAULT_NAMESPACE)
            .await;

        // Assert
        assert!(user.is_some());

        // Act
        let user = user.unwrap();
        assert_eq!(user.username, USERNAME);

        // Act
        let groups = service
            .get_user_group_names(user.user_id, DEFAULT_NAMESPACE)
            .await
            .unwrap();
        let token = jwt_service
            .generate_token(
                user.user_id,
                &user.username,
                &user.email,
                groups,
                DEFAULT_NAMESPACE,
                user.organization_id,
            )
            .unwrap();

        // Assert
        assert!(!token.is_empty());

        // Act
        let new_token = NewPasswordResetToken {
            user_id: user.user_id,
            token: token.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
        };

        let result = service
            .password_reset_repo
            .create_reset_token(new_token, DEFAULT_NAMESPACE)
            .await;

        // Assert
        assert!(result.is_ok());

        // Act
        let settings = settings_service
            .get_all_settings(DEFAULT_NAMESPACE)
            .await
            .unwrap();

        // Assert
        assert!(!settings.is_empty());
        assert_eq!(settings[0].key, "BASE_URL");
    }

    #[tokio::test]
    async fn test_recover_user_with_invalid_username() {
        // Setup
        let user_repo = Arc::new(MockUserRepo::new());
        let group_repo = Arc::new(MockGroupRepo);
        let password_reset_repo = Arc::new(MockPasswordResetRepo);
        let jwt_service = Arc::new(keyrunes::services::jwt_service::JwtService::new(
            "test_secret",
        ));
        let settings_repo = Arc::new(MockSettingsRepo);
        let settings_service = Arc::new(SettingsService::new(settings_repo));
        let _org_repo = Arc::new(MockOrganizationRepo);

        let service = UserService::new(
            user_repo,
            group_repo,
            Arc::new(MockOrganizationRepo),
            password_reset_repo,
            jwt_service,
            settings_service,
            None,
        );

        // Act
        let user = service
            .find_user_by_username("nonexistent", DEFAULT_NAMESPACE)
            .await;

        // Assert
        assert!(user.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_admin_changes_user_password_successfully() {
        setup_cli_test_db().await;
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            std::env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:password@localhost:5432/keyrunes".to_string())
        });

        // Setup
        let output = Command::new("./target/debug/cli")
            .env("DATABASE_URL", &db_url)
            .args([
                "set-user-password",
                "--email",
                EMAIL,
                "--set-password",
                "--password",
                PASSWORD,
            ])
            .output()
            .expect("Failed to execute command");

        // Act
        let stdout = String::from_utf8(output.stdout).unwrap();

        // Assert
        assert!(output.status.success());
        assert!(stdout.contains("Updated password successfully"));
    }

    #[tokio::test]
    #[serial]
    async fn test_admin_changes_user_password_unsuccessfully() {
        setup_cli_test_db().await;
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            std::env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:password@localhost:5432/keyrunes".to_string())
        });

        // Setup
        let err = &EMAIL[9..];
        let output = Command::new("./target/debug/cli")
            .env("DATABASE_URL", &db_url)
            .args([
                "set-user-password",
                "--email",
                err,
                "--set-password",
                "--password",
                PASSWORD,
            ])
            .output()
            .expect("Failed to execute command");

        // Act
        let stderr = String::from_utf8(output.stderr).unwrap();

        // Assert
        assert!(!output.status.success());
        assert!(stderr.contains(format!("Error: User with email {} not found", err).as_str()));
    }

    #[tokio::test]
    #[serial]
    async fn test_recover_user_with_url_successfully() {
        setup_cli_test_db().await;
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            std::env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:password@localhost:5432/keyrunes".to_string())
        });

        // Setup
        let output = Command::new("./target/debug/cli")
            .env("DATABASE_URL", &db_url)
            .args(["recover-user", "--username", USERNAME, "--generate-token"])
            .output()
            .expect("Failed to execute command");

        // Act
        let stdout = String::from_utf8(output.stdout).unwrap();

        // Assert
        if !output.status.success() {
            println!(
                "Command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(output.status.success());
        assert!(stdout.contains("http://localhost:3000"));
    }

    #[tokio::test]
    #[serial]
    async fn test_recover_user_with_url_unsuccessfully() {
        setup_cli_test_db().await;
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            std::env::var("DATABASE_URL")
                .unwrap_or("postgres://postgres:password@localhost:5432/keyrunes".to_string())
        });

        // Setup
        let err = &USERNAME[3..];
        let output = Command::new("./target/debug/cli")
            .env("DATABASE_URL", &db_url)
            .args(["recover-user", "--username", err, "--generate-token"])
            .output()
            .expect("Failed to execute command");

        // Act
        let stderr = String::from_utf8(output.stderr).unwrap();

        // Assert
        assert!(!output.status.success());
        assert!(stderr.contains(format!("User {} not found", err).as_str()));
    }
}
