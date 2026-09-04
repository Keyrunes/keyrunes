/// Default namespace for public/default tenant
pub const DEFAULT_NAMESPACE: &str = "public";

/// Default organization ID
pub const DEFAULT_ORGANIZATION_ID: i64 = 1;

/// Default admin credentials (used in tests and initial setup)
pub const DEFAULT_ADMIN_EMAIL: &str = "admin@example.com";
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";

/// Default group names
pub const SUPERADMIN_GROUP: &str = "superadmin";
pub const ADMIN_GROUP: &str = "admin";
pub const USERS_GROUP: &str = "users";

/// Groups that carry administrative authority and therefore may never be
/// chosen by the caller of an unauthenticated registration.
///
/// `/register` and `/api/register` are public routes that accept a `group`
/// field, and group assignment is by name. Without this list anyone could post
/// `{"group": "superadmin"}` and be granted it. Assigning these remains
/// possible through the authenticated admin paths, and the bootstrap of the
/// very first user is unaffected.
pub const PRIVILEGED_GROUPS: [&str; 2] = [SUPERADMIN_GROUP, ADMIN_GROUP];

/// Whether `group` names a group an anonymous registration must not self-assign.
///
/// Compared case-insensitively and ignoring surrounding whitespace, because
/// group resolution trims the name before looking it up.
pub fn is_privileged_group(group: &str) -> bool {
    let group = group.trim();
    PRIVILEGED_GROUPS
        .iter()
        .any(|privileged| privileged.eq_ignore_ascii_case(group))
}

/// Password validation
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// JWT token  
pub const DEFAULT_JWT_SECRET: &str = "0123456789ABCDEF0123456789ABCDEF";
