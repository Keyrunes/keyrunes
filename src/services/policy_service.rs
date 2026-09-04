use crate::repository::{NewPolicy, Policy, PolicyEffect, PolicyRepository};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePolicyRequest {
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: PolicyEffect,
    pub conditions: Option<JsonValue>,
}

impl From<Policy> for PolicyResponse {
    fn from(policy: Policy) -> Self {
        Self {
            policy_id: policy.policy_id,
            external_id: policy.external_id,
            name: policy.name,
            description: policy.description,
            resource: policy.resource,
            action: policy.action,
            effect: policy.effect,
            conditions: policy.conditions,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PolicyService<P: PolicyRepository> {
    pub repo: Arc<P>,
}

#[allow(dead_code)]
impl<P: PolicyRepository> PolicyService<P> {
    /// Creates a new `PolicyService` instance.
    pub fn new(repo: Arc<P>) -> Self {
        Self { repo }
    }

    /// Creates a new policy.
    pub async fn create_policy(&self, req: CreatePolicyRequest, namespace: &str) -> Result<Policy> {
        if self
            .repo
            .find_by_name(&req.name, req.organization_id, namespace)
            .await?
            .is_some()
        {
            return Err(anyhow!("policy name already exists"));
        }

        if req.resource.is_empty() {
            return Err(anyhow!("resource cannot be empty"));
        }
        if req.action.is_empty() {
            return Err(anyhow!("action cannot be empty"));
        }

        let new_policy = NewPolicy {
            external_id: Uuid::new_v4(),
            organization_id: req.organization_id,
            name: req.name,
            description: req.description,
            resource: req.resource,
            action: req.action,
            effect: req.effect,
            conditions: req.conditions,
        };

        self.repo.insert_policy(new_policy, namespace).await
    }

    /// Finds a policy by its name within an organization.
    pub async fn get_policy_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Policy>> {
        self.repo
            .find_by_name(name, organization_id, namespace)
            .await
    }

    /// Finds a policy by its ID.
    pub async fn get_policy_by_id(
        &self,
        policy_id: i64,
        namespace: &str,
    ) -> Result<Option<Policy>> {
        self.repo.find_by_id(policy_id, namespace).await
    }

    /// Lists all policies in an organization.
    pub async fn list_policies(
        &self,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Vec<Policy>> {
        self.repo.list_policies(organization_id, namespace).await
    }

    /// Assigns a policy to a user.
    pub async fn assign_policy_to_user(
        &self,
        user_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        if self.repo.find_by_id(policy_id, namespace).await?.is_none() {
            return Err(anyhow!("policy not found"));
        }

        self.repo
            .assign_policy_to_user(user_id, policy_id, assigned_by, namespace)
            .await
    }

    /// Assigns a policy to a group.
    pub async fn assign_policy_to_group(
        &self,
        group_id: i64,
        policy_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        if self.repo.find_by_id(policy_id, namespace).await?.is_none() {
            return Err(anyhow!("policy not found"));
        }

        self.repo
            .assign_policy_to_group(group_id, policy_id, assigned_by, namespace)
            .await
    }

    /// Removes a policy from a user.
    pub async fn remove_policy_from_user(
        &self,
        user_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()> {
        self.repo
            .remove_policy_from_user(user_id, policy_id, namespace)
            .await
    }

    /// Removes a policy from a group.
    pub async fn remove_policy_from_group(
        &self,
        group_id: i64,
        policy_id: i64,
        namespace: &str,
    ) -> Result<()> {
        self.repo
            .remove_policy_from_group(group_id, policy_id, namespace)
            .await
    }

    /// Evaluate if a user has permission for a specific resource and action
    pub async fn evaluate_permission(
        &self,
        user_policies: &[Policy],
        resource: &str,
        action: &str,
    ) -> bool {
        let mut allow = false;
        let mut deny = false;

        for policy in user_policies {
            if self.matches_policy(policy, resource, action) {
                match policy.effect {
                    PolicyEffect::Allow => allow = true,
                    PolicyEffect::Deny => deny = true,
                }
            }
        }

        allow && !deny
    }

    fn matches_policy(&self, policy: &Policy, resource: &str, action: &str) -> bool {
        let resource_match = policy.resource == "*" || policy.resource == resource || {
            if policy.resource.ends_with("*") {
                let prefix = &policy.resource[..policy.resource.len() - 1];
                resource.starts_with(prefix)
            } else {
                false
            }
        };

        let action_match = policy.action == "*" || policy.action == action;

        resource_match && action_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_NAMESPACE;
    use crate::repository::{Policy, PolicyEffect};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;
    use exhaustive::{Exhaustive, exhaustive_test};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct MockPolicyRepository {
        policies: Mutex<Vec<Policy>>,
        user_policies: Mutex<Vec<(i64, i64)>>,
        group_policies: Mutex<Vec<(i64, i64)>>,
    }

    impl MockPolicyRepository {
        fn new() -> Self {
            Self {
                policies: Mutex::new(Vec::new()),
                user_policies: Mutex::new(Vec::new()),
                group_policies: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PolicyRepository for MockPolicyRepository {
        async fn find_by_name(
            &self,
            name: &str,
            _organization_id: i64,
            _namespace: &str,
        ) -> Result<Option<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.iter().find(|p| p.name == name).cloned())
        }

        async fn find_by_id(&self, policy_id: i64, _namespace: &str) -> Result<Option<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.iter().find(|p| p.policy_id == policy_id).cloned())
        }

        async fn insert_policy(&self, new_policy: NewPolicy, _namespace: &str) -> Result<Policy> {
            let mut policies = self.policies.lock().unwrap();
            let policy = Policy {
                policy_id: (policies.len() + 1) as i64,
                external_id: new_policy.external_id,
                organization_id: new_policy.organization_id,
                name: new_policy.name,
                description: new_policy.description,
                resource: new_policy.resource,
                action: new_policy.action,
                effect: new_policy.effect,
                conditions: new_policy.conditions,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            policies.push(policy.clone());
            Ok(policy)
        }

        async fn list_policies(
            &self,
            _organization_id: i64,
            _namespace: &str,
        ) -> Result<Vec<Policy>> {
            let policies = self.policies.lock().unwrap();
            Ok(policies.clone())
        }

        async fn assign_policy_to_user(
            &self,
            user_id: i64,
            policy_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            let mut user_policies = self.user_policies.lock().unwrap();
            user_policies.push((user_id, policy_id));
            Ok(())
        }

        async fn assign_policy_to_group(
            &self,
            group_id: i64,
            policy_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            let mut group_policies = self.group_policies.lock().unwrap();
            group_policies.push((group_id, policy_id));
            Ok(())
        }

        async fn remove_policy_from_user(
            &self,
            user_id: i64,
            policy_id: i64,
            _namespace: &str,
        ) -> Result<()> {
            let mut user_policies = self.user_policies.lock().unwrap();
            user_policies.retain(|(uid, pid)| !(*uid == user_id && *pid == policy_id));
            Ok(())
        }

        async fn remove_policy_from_group(
            &self,
            group_id: i64,
            policy_id: i64,
            _namespace: &str,
        ) -> Result<()> {
            let mut group_policies = self.group_policies.lock().unwrap();
            group_policies.retain(|(gid, pid)| !(*gid == group_id && *pid == policy_id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_policy() {
        // Setup
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let req = CreatePolicyRequest {
            organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
            name: "test_policy".to_string(),
            description: Some("Test policy".to_string()),
            resource: "user:*".to_string(),
            action: "read".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
        };

        // Act
        let policy = service.create_policy(req, DEFAULT_NAMESPACE).await.unwrap();

        // Assert
        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.resource, "user:*");
        assert_eq!(policy.action, "read");
        assert_eq!(policy.effect, PolicyEffect::Allow);
    }

    #[tokio::test]
    async fn test_evaluate_permission() {
        // Setup
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let policies = vec![
            Policy {
                policy_id: 1,
                external_id: Uuid::new_v4(),
                organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
                name: "allow_read".to_string(),
                description: None,
                resource: "user:*".to_string(),
                action: "read".to_string(),
                effect: PolicyEffect::Allow,
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Policy {
                policy_id: 2,
                external_id: Uuid::new_v4(),
                organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
                name: "deny_delete".to_string(),
                description: None,
                resource: "*".to_string(),
                action: "delete".to_string(),
                effect: PolicyEffect::Deny,
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        // Act & Assert
        assert!(
            service
                .evaluate_permission(&policies, "user:123", "read")
                .await
        );

        assert!(
            !service
                .evaluate_permission(&policies, "user:123", "delete")
                .await
        );

        assert!(
            !service
                .evaluate_permission(&policies, "user:123", "write")
                .await
        );
    }

    #[tokio::test]
    async fn test_wildcard_matching() {
        let repo = Arc::new(MockPolicyRepository::new());
        let service = PolicyService::new(repo);

        let policy = Policy {
            policy_id: 1,
            external_id: Uuid::new_v4(),
            organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
            name: "wildcard_policy".to_string(),
            description: None,
            resource: "api:*".to_string(),
            action: "*".to_string(),
            effect: PolicyEffect::Allow,
            conditions: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(service.matches_policy(&policy, "api:users", "read"));
        assert!(service.matches_policy(&policy, "api:admin", "write"));

        assert!(!service.matches_policy(&policy, "database:users", "read"));
    }

    // ---------------------------------------------------------------------
    // Exhaustive authorization tests.
    //
    // `evaluate_permission` is the decision point for every authorization
    // question Keyrunes answers, so it is enumerated rather than sampled: the
    // `exhaustive` crate walks *every* combination of the modelled policy
    // space, and each case is checked against invariants that hold no matter
    // how matching is implemented.
    // ---------------------------------------------------------------------

    /// The distinct shapes a policy's `resource` can take relative to the
    /// resource being asked about. Concrete strings are chosen by
    /// [`PolicySpec::resource_pattern`].
    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum ResourcePattern {
        /// `*` — the catch-all.
        Star,
        /// Exactly the requested resource.
        Exact,
        /// A prefix glob that covers the requested resource (`user:*`).
        MatchingGlob,
        /// A prefix glob that does not (`billing:*`).
        ForeignGlob,
        /// An unrelated exact resource.
        Foreign,
        /// A bare `*` suffix on an empty prefix, which reaches the glob branch
        /// with an empty prefix — every resource starts with "".
        EmptyGlob,
    }

    /// The shapes a policy's `action` can take relative to the asked action.
    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum ActionPattern {
        Star,
        Exact,
        Foreign,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum Effect {
        Allow,
        Deny,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    struct PolicySpec {
        effect: Effect,
        resource: ResourcePattern,
        action: ActionPattern,
    }

    /// The resource and action every exhaustive case asks about.
    const ASKED_RESOURCE: &str = "user:123";
    const ASKED_ACTION: &str = "read";

    impl PolicySpec {
        fn resource_pattern(self) -> &'static str {
            match self.resource {
                ResourcePattern::Star => "*",
                ResourcePattern::Exact => ASKED_RESOURCE,
                ResourcePattern::MatchingGlob => "user:*",
                ResourcePattern::ForeignGlob => "billing:*",
                ResourcePattern::Foreign => "billing:123",
                ResourcePattern::EmptyGlob => "*",
            }
        }

        fn action_pattern(self) -> &'static str {
            match self.action {
                ActionPattern::Star => "*",
                ActionPattern::Exact => ASKED_ACTION,
                ActionPattern::Foreign => "delete",
            }
        }

        /// Whether this policy is expected to apply to the asked pair. Derived
        /// from the *pattern shapes*, not from the implementation, so it is an
        /// independent statement of the intended semantics.
        fn applies(self) -> bool {
            let resource_applies = matches!(
                self.resource,
                ResourcePattern::Star
                    | ResourcePattern::Exact
                    | ResourcePattern::MatchingGlob
                    | ResourcePattern::EmptyGlob
            );
            let action_applies = matches!(self.action, ActionPattern::Star | ActionPattern::Exact);
            resource_applies && action_applies
        }

        fn to_policy(self, policy_id: i64) -> Policy {
            Policy {
                policy_id,
                external_id: Uuid::new_v4(),
                organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
                name: format!("policy_{policy_id}"),
                description: None,
                resource: self.resource_pattern().to_string(),
                action: self.action_pattern().to_string(),
                effect: match self.effect {
                    Effect::Allow => PolicyEffect::Allow,
                    Effect::Deny => PolicyEffect::Deny,
                },
                conditions: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }
    }

    /// Run `evaluate_permission` on a private current-thread runtime.
    ///
    /// The exhaustive macro generates plain `#[test]` functions, and building
    /// one runtime per case keeps the cases independent.
    fn decide(policies: &[Policy]) -> bool {
        let service = PolicyService::new(Arc::new(MockPolicyRepository::new()));
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build a test runtime")
            .block_on(service.evaluate_permission(policies, ASKED_RESOURCE, ASKED_ACTION))
    }

    fn build(specs: &[Option<PolicySpec>]) -> Vec<Policy> {
        specs
            .iter()
            .flatten()
            .enumerate()
            .map(|(i, spec)| spec.to_policy(i as i64 + 1))
            .collect()
    }

    /// Every pair of policies, including the empty and single-policy cases:
    /// 31 x 31 = 961 combinations, each checked against the access-control
    /// invariants the service is supposed to guarantee.
    #[exhaustive_test]
    fn evaluate_permission_holds_its_invariants(a: Option<PolicySpec>, b: Option<PolicySpec>) {
        let specs = [a, b];
        let policies = build(&specs);
        let granted = decide(&policies);

        let applicable: Vec<PolicySpec> = specs
            .iter()
            .flatten()
            .copied()
            .filter(|s| s.applies())
            .collect();
        let has_allow = applicable.iter().any(|s| s.effect == Effect::Allow);
        let has_deny = applicable.iter().any(|s| s.effect == Effect::Deny);

        // 1. Default deny: without an applicable Allow, nothing is granted.
        if !has_allow {
            assert!(!granted, "granted without an applicable allow: {specs:?}");
        }

        // 2. Deny wins: one applicable Deny overrides every Allow.
        if has_deny {
            assert!(!granted, "an applicable deny did not override: {specs:?}");
        }

        // 3. The only way to be granted.
        assert_eq!(
            granted,
            has_allow && !has_deny,
            "decision disagreed with the policy shapes: {specs:?}"
        );
    }

    /// The decision must not depend on the order policies arrive in.
    #[exhaustive_test]
    fn evaluate_permission_is_order_independent(a: Option<PolicySpec>, b: Option<PolicySpec>) {
        let forward = build(&[a, b]);
        let mut reversed = forward.clone();
        reversed.reverse();

        assert_eq!(
            decide(&forward),
            decide(&reversed),
            "order changed the decision: {a:?} {b:?}"
        );
    }

    /// Evaluating the same policy twice must not change the answer.
    #[exhaustive_test]
    fn evaluate_permission_is_idempotent_under_duplication(spec: Option<PolicySpec>) {
        let once = build(&[spec]);
        let twice = build(&[spec, spec]);

        assert_eq!(
            decide(&once),
            decide(&twice),
            "duplication changed the decision: {spec:?}"
        );
    }

    /// Adding a policy can never turn a denial into a grant when the added
    /// policy is a Deny: authorization must be monotonically restrictive.
    #[exhaustive_test]
    fn adding_a_deny_never_grants(
        base: Option<PolicySpec>,
        added_resource: ResourcePattern,
        added_action: ActionPattern,
    ) {
        let before = decide(&build(&[base]));

        let deny = PolicySpec {
            effect: Effect::Deny,
            resource: added_resource,
            action: added_action,
        };
        let after = decide(&build(&[base, Some(deny)]));

        assert!(
            !(after && !before),
            "adding a deny granted access it had refused: base {base:?} deny {deny:?}"
        );
    }

    /// Dropping an Allow can never turn a denial into a grant.
    #[exhaustive_test]
    fn dropping_an_allow_never_grants(
        kept: Option<PolicySpec>,
        dropped_resource: ResourcePattern,
        dropped_action: ActionPattern,
    ) {
        let allow = PolicySpec {
            effect: Effect::Allow,
            resource: dropped_resource,
            action: dropped_action,
        };

        let with_allow = decide(&build(&[kept, Some(allow)]));
        let without = decide(&build(&[kept]));

        assert!(
            !(without && !with_allow),
            "removing an allow granted access: kept {kept:?} dropped {allow:?}"
        );
    }
}
