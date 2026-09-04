//! Tests for the admin view's access gate.
//!
//! `admin_page` itself can only be called with a live `PgPool` extension, so
//! the gate is exercised through `may_view_admin`, the function it delegates
//! to. Membership is enumerated rather than sampled: this decides who reaches
//! the administrative surface, and the interesting cases are the ones a
//! sampled test would not think to write down — a group whose name merely
//! contains "admin", a privileged group sitting behind several others, the
//! empty set.

use exhaustive::{Exhaustive, exhaustive_test};
use keyrunes::constants::{ADMIN_GROUP, SUPERADMIN_GROUP, USERS_GROUP};
use keyrunes::views::admin::may_view_admin;

/// One membership a user may hold, and whether it alone opens the gate.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum Membership {
    Superadmin,
    Admin,
    Users,
    /// A group whose name contains "admin" without being it.
    AdminLookalike,
    /// A group whose name is `admin` with different casing.
    AdminWrongCase,
    /// An unrelated application group.
    Unrelated,
}

impl Membership {
    fn name(self) -> &'static str {
        match self {
            Membership::Superadmin => SUPERADMIN_GROUP,
            Membership::Admin => ADMIN_GROUP,
            Membership::Users => USERS_GROUP,
            Membership::AdminLookalike => "administrators",
            Membership::AdminWrongCase => "Admin",
            Membership::Unrelated => "instructor",
        }
    }

    /// Only the two privileged groups grant access, matched exactly.
    fn grants(self) -> bool {
        matches!(self, Membership::Superadmin | Membership::Admin)
    }
}

fn groups_of(memberships: &[Option<Membership>]) -> Vec<String> {
    memberships
        .iter()
        .flatten()
        .map(|m| m.name().to_string())
        .collect()
}

/// Every membership set of up to three groups: 7 x 7 x 7 = 343 combinations.
///
/// Access is granted exactly when a privileged group is present, wherever it
/// sits in the list and whatever else is alongside it.
#[exhaustive_test]
fn the_admin_gate_opens_only_for_a_privileged_group(
    first: Option<Membership>,
    second: Option<Membership>,
    third: Option<Membership>,
) {
    let memberships = [first, second, third];
    let groups = groups_of(&memberships);

    let expected = memberships.iter().flatten().any(|m| m.grants());

    assert_eq!(
        may_view_admin(&groups),
        expected,
        "wrong decision for {groups:?}"
    );
}

/// A user holding nothing at all must not reach the admin page.
#[test]
fn the_admin_gate_is_closed_by_default() {
    assert!(!may_view_admin(&[]));
}

/// Adding an ordinary group can never open the gate on its own, and can never
/// close one a privileged group had opened.
#[exhaustive_test]
fn an_ordinary_group_never_changes_the_decision(held: Option<Membership>, added: Membership) {
    if added.grants() {
        return;
    }

    let before = may_view_admin(&groups_of(&[held]));
    let after = may_view_admin(&groups_of(&[held, Some(added)]));

    assert_eq!(before, after, "{added:?} changed the decision for {held:?}");
}
