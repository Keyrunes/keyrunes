use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A tenant organization, isolated from the others by its `namespace` schema.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub organization_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// The organization's API key, presented as `X-Organization-Key` by
    /// machine clients (rotated via `POST /api/org/secret/rotate`).
    pub secret_key: Uuid,
    pub namespace: String,
    pub base_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Payload accepted by `POST /api/organizations`; the server mints
/// `external_id` and `secret_key`, so they are not part of the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrganization {
    pub name: String,
    pub description: Option<String>,
    pub namespace: String,
    pub base_url: Option<String>,
}
