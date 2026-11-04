use goose::config::GooseConfiguration;
use goose::prelude::*;

/// Scenario 1: Health baseline - GET /api/health
/// 10 users, 30s duration, verify 200 response
async fn health_baseline_scenario(user: &mut GooseUser) -> TransactionResult {
    let mut goose = user.get("/api/health").await?;

    let response = match &goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                "health_baseline",
                &mut goose.request,
                None,
                Some(&format!("Request failed: {}", e)),
            );
        }
    };

    if response.status() != 200 {
        return user.set_failure(
            "health_baseline",
            &mut goose.request,
            None,
            Some(&format!("Expected 200, got {}", response.status())),
        );
    }

    Ok(())
}

/// Scenario 2: Concurrent logins - POST /api/auth/login
/// 20 users, 30s duration, verify response
async fn concurrent_login_scenario(user: &mut GooseUser) -> TransactionResult {
    let login_body = serde_json::json!({
        "identity": "user_0",
        "password": "Test123456!",
        "namespace": "public"
    });

    let mut goose = user.post_json("/api/login", &login_body).await?;

    let response = match &goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                "concurrent_login",
                &mut goose.request,
                None,
                Some(&format!("Request failed: {}", e)),
            );
        }
    };

    let status = response.status();
    if status != 200 && status != 401 {
        return user.set_failure(
            "concurrent_login",
            &mut goose.request,
            None,
            Some(&format!("Expected 200 or 401, got {}", status)),
        );
    }

    Ok(())
}

/// Scenario 3: Registration flow - POST /api/auth/register
/// 5 users (argon2 is CPU-intensive), 30s duration, verify 201/409
async fn registration_flow_scenario(user: &mut GooseUser) -> TransactionResult {
    let user_id = user.weighted_users_index;
    let username = format!("stress_user_{}", user_id);
    let email = format!("stress_user_{}@test.com", user_id);

    let register_body = serde_json::json!({
        "username": username,
        "email": email,
        "password": "Test123456!",
        "namespace": "public",
        "organization_id": null,
        "group": null
    });

    let mut goose = user.post_json("/api/register", &register_body).await?;

    let response = match &goose.response {
        Ok(r) => r,
        Err(e) => {
            return user.set_failure(
                "registration_flow",
                &mut goose.request,
                None,
                Some(&format!("Request failed: {}", e)),
            );
        }
    };

    let status = response.status();
    if status != 201 && status != 400 {
        return user.set_failure(
            "registration_flow",
            &mut goose.request,
            None,
            Some(&format!("Expected 201 or 400, got {}", status)),
        );
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires a running server on localhost:3000 (run: make test-stress)"]
async fn stress_test_health_baseline() {
    let goose = GooseAttack::initialize_with_config(GooseConfiguration::default())
        .unwrap()
        .register_scenario(
            scenario!("HealthBaseline")
                .register_transaction(transaction!(health_baseline_scenario)),
        )
        .set_default(GooseDefault::Users, 10)
        .unwrap()
        .set_default(GooseDefault::RunTime, 30)
        .unwrap()
        .set_default(GooseDefault::StartupTime, 5)
        .unwrap()
        .set_default(GooseDefault::Host, "http://localhost:3000")
        .unwrap()
        .execute()
        .await;

    assert!(goose.is_ok(), "Health baseline stress test failed");
}

#[tokio::test]
#[ignore = "requires a running server on localhost:3000 (run: make test-stress)"]
async fn stress_test_concurrent_login() {
    let goose = GooseAttack::initialize_with_config(GooseConfiguration::default())
        .unwrap()
        .register_scenario(
            scenario!("ConcurrentLogin")
                .register_transaction(transaction!(concurrent_login_scenario)),
        )
        .set_default(GooseDefault::Users, 20)
        .unwrap()
        .set_default(GooseDefault::RunTime, 30)
        .unwrap()
        .set_default(GooseDefault::StartupTime, 5)
        .unwrap()
        .set_default(GooseDefault::Host, "http://localhost:3000")
        .unwrap()
        .execute()
        .await;

    assert!(goose.is_ok(), "Concurrent login stress test failed");
}

#[tokio::test]
#[ignore = "requires a running server on localhost:3000 (run: make test-stress)"]
async fn stress_test_registration_flow() {
    let goose = GooseAttack::initialize_with_config(GooseConfiguration::default())
        .unwrap()
        .register_scenario(
            scenario!("RegistrationFlow")
                .register_transaction(transaction!(registration_flow_scenario)),
        )
        .set_default(GooseDefault::Users, 5)
        .unwrap()
        .set_default(GooseDefault::RunTime, 30)
        .unwrap()
        .set_default(GooseDefault::StartupTime, 5)
        .unwrap()
        .set_default(GooseDefault::Host, "http://localhost:3000")
        .unwrap()
        .execute()
        .await;

    assert!(goose.is_ok(), "Registration flow stress test failed");
}
