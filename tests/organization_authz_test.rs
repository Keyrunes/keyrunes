//! Regression tests for the organization listing authorization.
//!
//! The `GET /api/admin/organizations` payload carries the organization
//! `secret_key` (the organization API key), so a plain user must never be
//! able to call it — and a tenant administrator must only ever see the
//! organizations of its own namespace (C11-007 / C11-008 family).

use keyrunes::api::organization::may_list_organizations;
use keyrunes::handler::auth::AuthenticatedUser;

/// Build an authenticated principal with the given namespace and groups.
fn principal(namespace: &str, groups: &[&str]) -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: 1,
        email: "user@sentinel-poc.local".to_string(),
        username: "sentinel-poc".to_string(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        namespace: namespace.to_string(),
        organization_id: 1,
    }
}

#[test]
fn a_plain_user_may_not_list_organizations() {
    assert!(!may_list_organizations(&principal("public", &["users"])));
    assert!(!may_list_organizations(&principal("tenant-a", &["users"])));
}

#[test]
fn a_tenant_administrator_may_list_organizations() {
    assert!(may_list_organizations(&principal("tenant-a", &["admin"])));
    assert!(may_list_organizations(&principal(
        "tenant-a",
        &["users", "admin"]
    )));
}

#[test]
fn a_global_superadmin_may_list_organizations() {
    assert!(may_list_organizations(&principal(
        "public",
        &["users", "superadmin"]
    )));
}

#[test]
fn a_tenant_superadmin_is_not_a_global_superadmin() {
    // The group name alone must not grant global reach: the namespace is what
    // separates a tenant administrator from the global one (C11-007).
    let tenant_superadmin = principal("tenant-a", &["superadmin"]);

    assert!(!tenant_superadmin.is_global_superadmin());
    assert!(may_list_organizations(&tenant_superadmin));
}
