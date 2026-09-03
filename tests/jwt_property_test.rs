//! Property-based and fuzz ("spider") tests for the JWT service.
//!
//! `JwtService` is the security boundary of the whole application and is pure
//! (no database, no clock injection beyond `Utc::now`), which makes it the
//! natural target for property testing. The suite covers two contracts:
//!
//! * a *round-trip* contract — every claim that goes into a token comes back
//!   out of it unchanged;
//! * a *robustness* contract — no input, however hostile, may panic, and no
//!   token signed by a different secret may ever verify.

use keyrunes::services::jwt_service::JwtService;
use proptest::prelude::*;

/// Secrets long enough for HS256 to accept.
fn secret() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{32,64}"
}

/// Claim text that survives a JSON round trip.
fn claim_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _.@-]{1,40}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    // ------------------------------------------------------------ round trip

    /// Every claim handed to `generate_token` must come back out of
    /// `verify_token` byte for byte.
    #[test]
    fn every_claim_survives_a_round_trip(
        secret in secret(),
        user_id in 1i64..1_000_000,
        email in claim_text(),
        username in claim_text(),
        groups in proptest::collection::vec("[a-z]{1,12}", 0..5),
        namespace in "[a-z][a-z0-9_-]{0,15}",
        organization_id in 1i64..100_000,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(
                user_id,
                &email,
                &username,
                groups.clone(),
                &namespace,
                organization_id,
            )
            .unwrap();

        let claims = service.verify_token(&token).unwrap();
        prop_assert_eq!(claims.sub, user_id.to_string());
        prop_assert_eq!(claims.email, email);
        prop_assert_eq!(claims.username, username);
        prop_assert_eq!(claims.groups, groups);
        prop_assert_eq!(claims.namespace, namespace);
        prop_assert_eq!(claims.organization_id, organization_id);
        prop_assert_eq!(claims.iss, "keyrunes");
    }

    /// A token is always issued with an expiry strictly after its issued-at.
    #[test]
    fn tokens_expire_after_they_are_issued(
        secret in secret(),
        user_id in 1i64..1_000_000,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();
        let claims = service.verify_token(&token).unwrap();
        prop_assert!(claims.exp > claims.iat, "exp {} <= iat {}", claims.exp, claims.iat);
    }

    /// `extract_user_id` must agree with the `sub` claim.
    #[test]
    fn extract_user_id_agrees_with_the_sub_claim(
        secret in secret(),
        user_id in 1i64..1_000_000,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();
        prop_assert_eq!(service.extract_user_id(&token).unwrap(), user_id);
    }

    /// Refreshing preserves the identity claims, only the timestamps move.
    #[test]
    fn refresh_preserves_identity_claims(
        secret in secret(),
        user_id in 1i64..1_000_000,
        email in claim_text(),
        username in claim_text(),
        groups in proptest::collection::vec("[a-z]{1,12}", 0..4),
        namespace in "[a-z][a-z0-9_-]{0,15}",
        organization_id in 1i64..100_000,
    ) {
        let service = JwtService::new(&secret);
        let original = service
            .generate_token(
                user_id, &email, &username, groups.clone(), &namespace, organization_id,
            )
            .unwrap();
        let refreshed = service.refresh_token(&original).unwrap();

        let before = service.verify_token(&original).unwrap();
        let after = service.verify_token(&refreshed).unwrap();
        prop_assert_eq!(after.sub, before.sub);
        prop_assert_eq!(after.email, before.email);
        prop_assert_eq!(after.username, before.username);
        prop_assert_eq!(after.groups, before.groups);
        prop_assert_eq!(after.namespace, before.namespace);
        prop_assert_eq!(after.organization_id, before.organization_id);
    }

    // -------------------------------------------------------------- security

    /// A token signed with one secret must never verify under another.
    #[test]
    fn a_token_never_verifies_under_a_different_secret(
        secret_a in secret(),
        secret_b in secret(),
        user_id in 1i64..1_000_000,
    ) {
        prop_assume!(secret_a != secret_b);
        let issuer = JwtService::new(&secret_a);
        let attacker = JwtService::new(&secret_b);

        let token = issuer
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();

        prop_assert!(issuer.verify_token(&token).is_ok());
        prop_assert!(
            attacker.verify_token(&token).is_err(),
            "token forged across secrets"
        );
    }

    /// Flipping any single character of the signature invalidates the token.
    #[test]
    fn tampering_with_the_signature_invalidates_the_token(
        secret in secret(),
        user_id in 1i64..1_000_000,
        offset in 0usize..20,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        prop_assume!(parts.len() == 3);
        let signature = parts[2].to_string();
        prop_assume!(!signature.is_empty());

        let index = offset % signature.len();
        let mut bytes = signature.into_bytes();
        // Swap the byte for a different, still base64url-safe one.
        bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
        let tampered_signature = String::from_utf8(bytes).unwrap();
        parts[2] = &tampered_signature;
        let tampered = parts.join(".");

        prop_assume!(tampered != token);
        prop_assert!(
            service.verify_token(&tampered).is_err(),
            "tampered signature accepted"
        );
    }

    /// Flipping a character of the payload invalidates the token too.
    #[test]
    fn tampering_with_the_payload_invalidates_the_token(
        secret in secret(),
        user_id in 1i64..1_000_000,
        offset in 0usize..40,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        prop_assume!(parts.len() == 3);
        let payload = parts[1].to_string();
        prop_assume!(!payload.is_empty());

        let index = offset % payload.len();
        let mut bytes = payload.into_bytes();
        bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
        let tampered_payload = String::from_utf8(bytes).unwrap();
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");

        prop_assume!(tampered != token);
        prop_assert!(
            service.verify_token(&tampered).is_err(),
            "tampered payload accepted"
        );
    }

    /// Dropping the signature entirely (the classic `alg: none` shape) must
    /// not be accepted.
    #[test]
    fn an_unsigned_token_is_rejected(
        secret in secret(),
        user_id in 1i64..1_000_000,
    ) {
        let service = JwtService::new(&secret);
        let token = service
            .generate_token(user_id, "a@b.com", "u", vec![], "public", 1)
            .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        prop_assume!(parts.len() == 3);

        let unsigned = format!("{}.{}.", parts[0], parts[1]);
        prop_assert!(service.verify_token(&unsigned).is_err());
    }

    // ------------------------------------------------------------- fuzzing

    /// Verifying arbitrary text must fail cleanly rather than panic.
    #[test]
    fn verifying_arbitrary_text_never_panics(
        secret in secret(),
        token in ".{0,120}",
    ) {
        let service = JwtService::new(&secret);
        let _ = service.verify_token(&token);
    }

    /// The same contract for JWT-shaped garbage: three dot-separated,
    /// base64url-looking segments that are not a real token.
    #[test]
    fn verifying_jwt_shaped_garbage_never_panics(
        secret in secret(),
        parts in proptest::collection::vec("[A-Za-z0-9_-]{0,30}", 0..5),
    ) {
        let service = JwtService::new(&secret);
        let token = parts.join(".");
        prop_assert!(service.verify_token(&token).is_err());
    }

    /// `extract_user_id` and `refresh_token` inherit the same robustness.
    #[test]
    fn derived_operations_never_panic_on_garbage(
        secret in secret(),
        token in ".{0,120}",
    ) {
        let service = JwtService::new(&secret);
        let _ = service.extract_user_id(&token);
        let _ = service.refresh_token(&token);
    }

    /// An empty secret must not make the service silently accept anything.
    #[test]
    fn tokens_from_an_empty_secret_service_do_not_verify_elsewhere(
        secret in secret(),
        user_id in 1i64..1_000_000,
    ) {
        let real = JwtService::new(&secret);
        let weak = JwtService::new("");
        // An empty HS256 key may or may not be accepted by the backend; what
        // matters is that its output is never trusted by the real service.
        if let Ok(token) = weak.generate_token(user_id, "a@b.com", "u", vec![], "public", 1) {
            prop_assert!(real.verify_token(&token).is_err());
        }
    }
}
