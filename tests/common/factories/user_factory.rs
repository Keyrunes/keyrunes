use chrono::Utc;
use fake::{
    Fake,
    faker::{
        company::en::CompanyName,
        internet::en::{SafeEmail, Username},
        name::en::{FirstName, LastName},
    },
};
use keyrunes::repository::User;
use uuid::Uuid;

pub struct UserFactory {
    user: User,
}

#[allow(dead_code)]
impl UserFactory {
    pub fn create_user(
        user_id: i64,
        username: String,
        email: String,
        organization_id: i64,
    ) -> User {
        Self::new()
            .user_id(user_id)
            .username(&username)
            .email(&email)
            .organization_id(organization_id)
            .finish()
    }

    /// Create a new factory with random data
    pub fn new() -> Self {
        Self {
            user: User {
                user_id: (1..1000).fake(),
                external_id: Uuid::new_v4(),
                organization_id: (1..100).fake(),
                email: SafeEmail().fake(),
                username: Username().fake(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$VEVTVA$dmVyeXNlY3JldA".to_string(),
                first_login: (0..2).fake::<i32>() == 1,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        }
    }

    /// Quick build with defaults (backwards compatible)
    pub fn build() -> User {
        Self::new().finish()
    }

    /// Build with specific organization
    pub fn build_with_org(organization_id: i64) -> User {
        Self::new().organization_id(organization_id).finish()
    }

    /// Build with specific email
    pub fn build_with_email(email: &str) -> User {
        Self::new().email(email).finish()
    }

    // Builder methods
    pub fn user_id(mut self, user_id: i64) -> Self {
        self.user.user_id = user_id;
        self
    }

    pub fn organization_id(mut self, organization_id: i64) -> Self {
        self.user.organization_id = organization_id;
        self
    }

    pub fn email(mut self, email: &str) -> Self {
        self.user.email = email.to_string();
        self
    }

    pub fn username(mut self, username: &str) -> Self {
        self.user.username = username.to_string();
        self
    }

    pub fn first_login(mut self, first_login: bool) -> Self {
        self.user.first_login = first_login;
        self
    }

    /// Generate realistic email from name pattern
    pub fn realistic_email(mut self) -> Self {
        let first: String = FirstName().fake();
        let last: String = LastName().fake();
        let company: String = CompanyName().fake();
        let domain = company
            .to_lowercase()
            .replace(' ', "")
            .chars()
            .take(10)
            .collect::<String>();
        self.user.email = format!(
            "{}.{}@{}.com",
            first.to_lowercase(),
            last.to_lowercase(),
            domain
        );
        self
    }

    /// Generate username from name
    pub fn realistic_username(mut self) -> Self {
        let first: String = FirstName().fake();
        let last: String = LastName().fake();
        let num: u32 = (1..999).fake();
        self.user.username = format!(
            "{}{}{}",
            first.to_lowercase(),
            last.to_lowercase().chars().next().unwrap_or('x'),
            num
        );
        self
    }

    /// Finish building and return the User
    pub fn finish(self) -> User {
        self.user
    }
}

impl Default for UserFactory {
    fn default() -> Self {
        Self::new()
    }
}
