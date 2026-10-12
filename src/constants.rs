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

/// Minimum accepted length for a `JWT_SECRET`.
///
/// HS256 exchanges a secret of arbitrary length and derives the HMAC key from
/// it, so a short secret is directly brute-forceable offline. 32 bytes matches
/// the SHA-256 output size and satisfies every guidance we follow.
pub const MIN_JWT_SECRET_LENGTH: usize = 32;

/// JWT secret used **only in tests**.
///
/// Production code must never fall back to a hardcoded secret: doing so once
/// (see the CVE-class auth bypass found during the security review) lets anyone
/// forge a superadmin token. The value is gated behind `#[cfg(test)]` so it is
/// not even compiled into release builds.
#[cfg(test)]
pub const DEFAULT_JWT_SECRET: &str = "0123456789ABCDEF0123456789ABCDEF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_groups_are_recognised_case_insensitively() {
        assert!(is_privileged_group("superadmin"));
        assert!(is_privileged_group("  ADMIN  "));
        assert!(!is_privileged_group("users"));
        assert!(!is_privileged_group(""));
    }

    #[test]
    fn min_jwt_secret_length_is_enforced_at_32() {
        assert_eq!(MIN_JWT_SECRET_LENGTH, 32);
    }

    /// The default secret must exist only for tests and must be long enough to
    /// pass the production length check, otherwise tests would fail startup.
    #[test]
    fn test_default_secret_meets_minimum_length() {
        assert!(DEFAULT_JWT_SECRET.len() >= MIN_JWT_SECRET_LENGTH);
    }
}
