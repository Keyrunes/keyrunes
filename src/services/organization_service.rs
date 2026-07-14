use crate::constants::{ADMIN_GROUP, USERS_GROUP};
use crate::domain::organization::NewOrganization;
use crate::repository::{GroupRepository, NewGroup, Organization, OrganizationRepository};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub namespace: String,
    pub base_url: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub description: Option<String>,
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    Ok(s.filter(|s| !s.trim().is_empty()))
}

#[derive(Debug, Clone)]
pub struct OrganizationService<O: OrganizationRepository, G: GroupRepository> {
    pub repo: Arc<O>,
    pub group_repo: Arc<G>,
}

impl<O: OrganizationRepository, G: GroupRepository> OrganizationService<O, G> {
    pub fn new(repo: Arc<O>, group_repo: Arc<G>) -> Self {
        Self { repo, group_repo }
    }

    pub async fn create_organization(
        &self,
        req: CreateOrganizationRequest,
    ) -> Result<Organization> {
        if self.repo.find_by_name(&req.name).await?.is_some() {
            return Err(anyhow!("organization already exists"));
        }

        // Basic validation for namespace
        if !req
            .namespace
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err(anyhow!(
                "namespace must be alphanumeric (underscores allowed)"
            ));
        }

        let new_org = NewOrganization {
            name: req.name,
            description: req.description,
            namespace: req.namespace.clone(),
            base_url: req.base_url,
        };

        let org = self.repo.insert_organization(new_org).await?;

        // Create default groups if they don't exist
        for group_name in [ADMIN_GROUP, USERS_GROUP] {
            if self
                .group_repo
                .find_by_name(group_name, org.organization_id, &req.namespace)
                .await?
                .is_none()
            {
                self.group_repo
                    .insert_group(
                        NewGroup {
                            external_id: Uuid::new_v4(),
                            organization_id: org.organization_id,
                            name: group_name.to_string(),
                            description: Some(match group_name {
                                ADMIN_GROUP => "Administrators of the organization".to_string(),
                                _ => "Standard users of the organization".to_string(),
                            }),
                        },
                        &req.namespace,
                    )
                    .await?;
            }
        }

        Ok(org)
    }

    pub async fn list_organizations(&self) -> Result<Vec<Organization>> {
        self.repo.list_organizations().await
    }

    pub async fn get_organization_by_id(
        &self,
        organization_id: i64,
    ) -> Result<Option<Organization>> {
        self.repo.find_by_id(organization_id).await
    }

    pub async fn get_organization_by_secret_key(
        &self,
        secret_key: Uuid,
    ) -> Result<Option<Organization>> {
        self.repo.find_by_secret_key(secret_key).await
    }

    pub async fn rotate_org_key(&self, organization_id: i64) -> Result<Uuid> {
        self.repo.rotate_secret_key(organization_id).await
    }

    pub async fn delete_organization(&self, organization_id: i64) -> Result<()> {
        self.repo.delete_organization(organization_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{Group, Policy};
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::sync::{Arc, Mutex};

    struct MockOrgRepository {
        orgs: Mutex<Vec<Organization>>,
    }

    impl MockOrgRepository {
        fn new() -> Self {
            Self {
                orgs: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OrganizationRepository for MockOrgRepository {
        async fn find_by_name(&self, name: &str) -> Result<Option<Organization>> {
            let orgs = self.orgs.lock().unwrap();
            Ok(orgs.iter().find(|o| o.name == name).cloned())
        }
        async fn find_by_id(&self, organization_id: i64) -> Result<Option<Organization>> {
            let orgs = self.orgs.lock().unwrap();
            Ok(orgs
                .iter()
                .find(|o| o.organization_id == organization_id)
                .cloned())
        }
        async fn find_by_namespace(&self, namespace: &str) -> Result<Option<Organization>> {
            let orgs = self.orgs.lock().unwrap();
            Ok(orgs.iter().find(|o| o.namespace == namespace).cloned())
        }
        async fn insert_organization(&self, new_org: NewOrganization) -> Result<Organization> {
            let mut orgs = self.orgs.lock().unwrap();
            let org = Organization {
                organization_id: (orgs.len() + 1) as i64,
                external_id: Uuid::new_v4(),
                name: new_org.name,
                description: new_org.description,
                namespace: new_org.namespace,
                base_url: new_org.base_url,
                secret_key: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            orgs.push(org.clone());
            Ok(org)
        }
        async fn list_organizations(&self) -> Result<Vec<Organization>> {
            Ok(self.orgs.lock().unwrap().clone())
        }
        async fn find_by_secret_key(&self, _secret_key: Uuid) -> Result<Option<Organization>> {
            unimplemented!()
        }
        async fn rotate_secret_key(&self, _organization_id: i64) -> Result<Uuid> {
            unimplemented!()
        }
        async fn delete_organization(&self, _organization_id: i64) -> Result<()> {
            unimplemented!()
        }
    }

    struct MockGroupRepository {
        groups: Mutex<Vec<Group>>,
    }

    impl MockGroupRepository {
        fn new() -> Self {
            Self {
                groups: Mutex::new(Vec::new()),
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
        async fn find_by_id(&self, _group_id: i64, _namespace: &str) -> Result<Option<Group>> {
            unimplemented!()
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
        async fn list_groups(&self, _organization_id: i64, _namespace: &str) -> Result<Vec<Group>> {
            unimplemented!()
        }
        async fn assign_user_to_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _assigned_by: Option<i64>,
            _namespace: &str,
        ) -> Result<()> {
            unimplemented!()
        }
        async fn remove_user_from_group(
            &self,
            _user_id: i64,
            _group_id: i64,
            _namespace: &str,
        ) -> Result<()> {
            unimplemented!()
        }
        async fn get_group_policies(
            &self,
            _group_id: i64,
            _namespace: &str,
        ) -> Result<Vec<Policy>> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_create_organization_with_default_groups() {
        // Setup
        let org_repo = Arc::new(MockOrgRepository::new());
        let group_repo = Arc::new(MockGroupRepository::new());
        let service = OrganizationService::new(org_repo, group_repo.clone());

        let req = CreateOrganizationRequest {
            name: "Test Org".to_string(),
            namespace: "test_org".to_string(),
            base_url: None,
            description: Some("Test Description".to_string()),
        };

        // Act
        let org = service.create_organization(req).await.unwrap();

        // Assert organization properties
        assert_eq!(org.name, "Test Org");
        assert_eq!(org.namespace, "test_org");

        // Assert default groups creation
        let groups = group_repo.groups.lock().unwrap();
        assert_eq!(groups.len(), 2);
        assert!(
            groups
                .iter()
                .any(|g| g.name == "admin" && g.organization_id == org.organization_id)
        );
        assert!(
            groups
                .iter()
                .any(|g| g.name == "users" && g.organization_id == org.organization_id)
        );
    }
}
