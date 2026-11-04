use crate::constants::{DEFAULT_NAMESPACE, SUPERADMIN_GROUP};
use crate::repository::{Group, GroupRepository, NewGroup};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Request body for `POST /api/admin/groups`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateGroupRequest {
    /// Tenant organization that will own the group; accepted as number or
    /// string (HTML forms submit strings).
    #[serde(deserialize_with = "crate::api::deserializers::deserialize_string_or_number")]
    pub organization_id: i64,
    pub name: String,
    pub description: Option<String>,
}

/// Serialized group with its attached policies, as returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct GroupResponse {
    pub group_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<PolicyResponse>,
}

/// Serialized policy embedded in a [`GroupResponse`].
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    pub policy_id: i64,
    pub external_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: String,
}

/// Group management on top of a tenant-scoped [`GroupRepository`].
#[derive(Debug, Clone)]
pub struct GroupService<G: GroupRepository> {
    pub repo: Arc<G>,
}

impl<G: GroupRepository> GroupService<G> {
    /// Creates a new `GroupService` instance.
    pub fn new(repo: Arc<G>) -> Self {
        Self { repo }
    }

    /// Creates a new group.
    ///
    /// SECURITY (C11-007): the `superadmin` name is reserved to the global
    /// namespace. Tenant schemas each carry a group by that name, and the
    /// authorization layers key off the name, so letting a tenant administrator
    /// mint one turns "I can name a group" into "I am a superadmin".
    pub async fn create_group(&self, req: CreateGroupRequest, namespace: &str) -> Result<Group> {
        if namespace != DEFAULT_NAMESPACE && req.name.trim().eq_ignore_ascii_case(SUPERADMIN_GROUP)
        {
            return Err(anyhow!(
                "group name '{}' is reserved to the global namespace",
                SUPERADMIN_GROUP
            ));
        }

        if self
            .repo
            .find_by_name(&req.name, req.organization_id, namespace)
            .await?
            .is_some()
        {
            return Err(anyhow!("group name already exists"));
        }

        let new_group = NewGroup {
            external_id: Uuid::new_v4(),
            organization_id: req.organization_id,
            name: req.name,
            description: req.description,
        };

        self.repo.insert_group(new_group, namespace).await
    }

    /// Finds a group by its name within an organization.
    pub async fn get_group_by_name(
        &self,
        name: &str,
        organization_id: i64,
        namespace: &str,
    ) -> Result<Option<Group>> {
        self.repo
            .find_by_name(name, organization_id, namespace)
            .await
    }

    /// Finds a group by its ID.
    pub async fn get_group_by_id(&self, group_id: i64, namespace: &str) -> Result<Option<Group>> {
        self.repo.find_by_id(group_id, namespace).await
    }

    /// Lists all groups in an organization.
    pub async fn list_groups(&self, organization_id: i64, namespace: &str) -> Result<Vec<Group>> {
        self.repo.list_groups(organization_id, namespace).await
    }

    /// Retrieves a group along with its associated policies.
    pub async fn get_group_with_policies(
        &self,
        group_id: i64,
        namespace: &str,
    ) -> Result<Option<GroupResponse>> {
        let group = self.repo.find_by_id(group_id, namespace).await?;

        if let Some(group) = group {
            let policies = self.repo.get_group_policies(group_id, namespace).await?;
            let policy_responses: Vec<PolicyResponse> = policies
                .into_iter()
                .map(|p| PolicyResponse {
                    policy_id: p.policy_id,
                    external_id: p.external_id,
                    name: p.name,
                    description: p.description,
                    resource: p.resource,
                    action: p.action,
                    effect: p.effect.to_string(),
                })
                .collect();

            Ok(Some(GroupResponse {
                group_id: group.group_id,
                external_id: group.external_id,
                name: group.name,
                description: group.description,
                policies: policy_responses,
            }))
        } else {
            Ok(None)
        }
    }

    /// Assigns a user to a group.
    ///
    /// SECURITY (C11-007): a tenant cannot grant `superadmin`, whatever the
    /// group row inside its own schema happens to be called.
    pub async fn assign_user_to_group(
        &self,
        user_id: i64,
        group_id: i64,
        assigned_by: Option<i64>,
        namespace: &str,
    ) -> Result<()> {
        let group = match self.repo.find_by_id(group_id, namespace).await? {
            Some(group) => group,
            None => return Err(anyhow!("group not found")),
        };

        if namespace != DEFAULT_NAMESPACE
            && group.name.trim().eq_ignore_ascii_case(SUPERADMIN_GROUP)
        {
            return Err(anyhow!(
                "group '{}' can only be assigned inside the global namespace",
                SUPERADMIN_GROUP
            ));
        }

        self.repo
            .assign_user_to_group(user_id, group_id, assigned_by, namespace)
            .await
    }

    /// Removes a user from a group.
    pub async fn remove_user_from_group(
        &self,
        user_id: i64,
        group_id: i64,
        namespace: &str,
    ) -> Result<()> {
        self.repo
            .remove_user_from_group(user_id, group_id, namespace)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_NAMESPACE;
    use crate::repository::{Group, Policy};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::sync::{Arc, Mutex};

    struct MockGroupRepository {
        groups: Mutex<Vec<Group>>,
        user_groups: Mutex<Vec<(i64, i64)>>,
    }

    impl MockGroupRepository {
        fn new() -> Self {
            Self {
                groups: Mutex::new(Vec::new()),
                user_groups: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl GroupRepository for MockGroupRepository {
        async fn find_by_name(
            &self,
            name: &str,
            organization_id: i64,
            _namespace: &str,
        ) -> Result<Option<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups
                .iter()
                .find(|g| g.name == name && g.organization_id == organization_id)
                .cloned())
        }

        async fn find_by_id(&self, group_id: i64, _namespace: &str) -> Result<Option<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
        }

        async fn insert_group(&self, new_group: NewGroup, _namespace: &str) -> Result<Group> {
            let mut groups = self.groups.lock().unwrap();
            let group = Group {
                group_id: (groups.len() + 1) as i64,
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

        async fn list_groups(&self, organization_id: i64, _namespace: &str) -> Result<Vec<Group>> {
            let groups = self.groups.lock().unwrap();
            Ok(groups
                .iter()
                .filter(|g| g.organization_id == organization_id)
                .cloned()
                .collect())
        }

        async fn assign_user_to_group(
            &self,
            user_id: i64,
            group_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            let mut user_groups = self.user_groups.lock().unwrap();
            user_groups.push((user_id, group_id));
            Ok(())
        }

        async fn remove_user_from_group(
            &self,
            user_id: i64,
            group_id: i64,
            _namespace: &str,
        ) -> Result<()> {
            let mut user_groups = self.user_groups.lock().unwrap();
            user_groups.retain(|(uid, gid)| !(*uid == user_id && *gid == group_id));
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

    #[tokio::test]
    async fn test_create_group() {
        let repo = Arc::new(MockGroupRepository::new());
        let service = GroupService::new(repo);

        let req = CreateGroupRequest {
            organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
            name: "test_group".to_string(),
            description: Some("Test group description".to_string()),
        };

        let group = service.create_group(req, DEFAULT_NAMESPACE).await.unwrap();

        assert_eq!(group.name, "test_group");
        assert_eq!(
            group.organization_id,
            crate::constants::DEFAULT_ORGANIZATION_ID
        );
        assert_eq!(
            group.description,
            Some("Test group description".to_string())
        );
    }

    #[tokio::test]
    async fn test_create_duplicate_group() {
        let repo = Arc::new(MockGroupRepository::new());
        let service = GroupService::new(repo);

        let req = CreateGroupRequest {
            organization_id: crate::constants::DEFAULT_ORGANIZATION_ID,
            name: "duplicate_group".to_string(),
            description: None,
        };

        service
            .create_group(req.clone(), DEFAULT_NAMESPACE)
            .await
            .unwrap();

        let result = service.create_group(req, DEFAULT_NAMESPACE).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "group name already exists");
    }
}
