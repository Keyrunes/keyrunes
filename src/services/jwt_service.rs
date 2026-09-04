use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use josekit::jws::HS256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub namespace: String,
    pub organization_id: i64,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

/// Lifetime of a freshly issued token.
const TOKEN_TTL_HOURS: i64 = 1;

/// Clock skew tolerated when checking `exp`, in seconds.
///
/// Keyrunes issues and verifies with the same clock, so this only absorbs the
/// sub-second drift between generating a token and checking it. Widening it
/// widens the window in which a revoked session still works.
const EXPIRY_LEEWAY_SECONDS: i64 = 0;

#[derive(Clone)]
pub struct JwtService {
    secret: Vec<u8>,
    issuer: String,
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            issuer: "keyrunes".to_string(),
        }
    }

    pub fn generate_token(
        &self,
        user_id: i64,
        email: &str,
        username: &str,
        groups: Vec<String>,
        namespace: &str,
        organization_id: i64,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(TOKEN_TTL_HOURS);

        let mut payload = JwtPayload::new();
        payload.set_claim("sub", Some(Value::String(user_id.to_string())))?;
        payload.set_claim("email", Some(Value::String(email.to_string())))?;
        payload.set_claim("username", Some(Value::String(username.to_string())))?;
        payload.set_claim("groups", Some(serde_json::to_value(&groups)?))?;
        payload.set_claim("namespace", Some(Value::String(namespace.to_string())))?;
        payload.set_claim(
            "organization_id",
            Some(Value::Number(organization_id.into())),
        )?;
        payload.set_claim("exp", Some(Value::Number(exp.timestamp().into())))?;
        payload.set_claim("iat", Some(Value::Number(now.timestamp().into())))?;
        payload.set_claim("iss", Some(Value::String(self.issuer.clone())))?;

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = HS256.signer_from_bytes(&self.secret)?;
        let token = jwt::encode_with_signer(&payload, &header, &signer)?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let verifier = HS256.verifier_from_bytes(&self.secret)?;
        let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
            .map_err(|e| anyhow!("Failed to decode JWT: {}", e))?;

        let sub = payload
            .claim("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'sub' claim"))?
            .to_string();
        let email = payload
            .claim("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'email' claim"))?
            .to_string();
        let username = payload
            .claim("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'username' claim"))?
            .to_string();
        let groups = payload
            .claim("groups")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Missing or invalid 'groups' claim"))?;
        let namespace = payload
            .claim("namespace")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'namespace' claim"))?
            .to_string();
        let organization_id = payload
            .claim("organization_id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing or invalid 'organization_id' claim"))?;
        let exp = payload
            .claim("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing or invalid 'exp' claim"))?;
        let iat = payload
            .claim("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing or invalid 'iat' claim"))?;
        let iss = payload
            .claim("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing or invalid 'iss' claim"))?
            .to_string();

        // `josekit::jwt::decode_with_verifier` only checks the signature; the
        // registered claims mean nothing unless they are checked here.
        if iss != self.issuer {
            return Err(anyhow!(
                "Token was issued by '{}', expected '{}'",
                iss,
                self.issuer
            ));
        }

        let now = Utc::now().timestamp();
        if now >= exp + EXPIRY_LEEWAY_SECONDS {
            return Err(anyhow!("Token expired at {} (now {})", exp, now));
        }

        Ok(Claims {
            sub,
            email,
            username,
            groups,
            namespace,
            organization_id,
            exp,
            iat,
            iss,
        })
    }

    pub fn refresh_token(&self, token: &str) -> Result<String> {
        let claims = self.verify_token(token)?;
        self.generate_token(
            claims.sub.parse()?,
            &claims.email,
            &claims.username,
            claims.groups,
            &claims.namespace,
            claims.organization_id,
        )
    }

    pub fn extract_user_id(&self, token: &str) -> Result<i64> {
        let claims = self.verify_token(token)?;
        claims
            .sub
            .parse()
            .map_err(|e| anyhow!("Invalid user ID in token: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::USERS_GROUP;
    use exhaustive::{Exhaustive, exhaustive_test};
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_jwt_token_generation_and_verification() {
        // Setup
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec![USERS_GROUP.to_string(), "admin".to_string()];

        // Act
        let token = service
            .generate_token(
                1,
                "test@example.com",
                "testuser",
                groups.clone(),
                "test_ns",
                1,
            )
            .unwrap();
        let claims = service.verify_token(&token).unwrap();

        // Assert
        assert_eq!(claims.sub, "1");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.groups, groups);
        assert_eq!(claims.namespace, "test_ns");
        assert_eq!(claims.iss, "keyrunes");
    }

    #[test]
    fn test_refresh_token() {
        // Setup
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec![USERS_GROUP.to_string()];
        let original_token = service
            .generate_token(
                1,
                "test@example.com",
                "testuser",
                groups.clone(),
                "test_ns",
                1,
            )
            .unwrap();
        thread::sleep(StdDuration::from_secs(1));

        // Act
        let refreshed_token = service.refresh_token(&original_token).unwrap();

        // Assert
        let original_claims = service.verify_token(&original_token).unwrap();
        let refreshed_claims = service.verify_token(&refreshed_token).unwrap();
        assert_eq!(original_claims.sub, refreshed_claims.sub);
        assert_eq!(original_claims.email, refreshed_claims.email);
        assert_eq!(original_claims.namespace, refreshed_claims.namespace);
        assert!(refreshed_claims.exp > original_claims.exp);
    }

    /// Sign a payload with `secret` without going through `generate_token`, so
    /// a test can put claims a well-behaved issuer would never emit.
    fn forge(secret: &str, exp: i64, iat: i64, iss: &str) -> String {
        let mut payload = JwtPayload::new();
        payload
            .set_claim("sub", Some(Value::String("1".into())))
            .unwrap();
        payload
            .set_claim("email", Some(Value::String("test@example.com".into())))
            .unwrap();
        payload
            .set_claim("username", Some(Value::String("testuser".into())))
            .unwrap();
        payload
            .set_claim("groups", Some(serde_json::json!([USERS_GROUP])))
            .unwrap();
        payload
            .set_claim("namespace", Some(Value::String("test_ns".into())))
            .unwrap();
        payload
            .set_claim("organization_id", Some(Value::Number(1.into())))
            .unwrap();
        payload
            .set_claim("exp", Some(Value::Number(exp.into())))
            .unwrap();
        payload
            .set_claim("iat", Some(Value::Number(iat.into())))
            .unwrap();
        payload
            .set_claim("iss", Some(Value::String(iss.into())))
            .unwrap();

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let signer = HS256.signer_from_bytes(secret.as_bytes()).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    #[test]
    fn an_expired_token_is_rejected() {
        // Setup: correctly signed, but expired two days ago.
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);
        let past = (Utc::now() - Duration::hours(48)).timestamp();

        // Act
        let result = service.verify_token(&forge(secret, past, past - 3600, "keyrunes"));

        // Assert
        assert!(result.is_err(), "an expired token must not verify");
    }

    #[test]
    fn a_token_expiring_one_second_from_now_still_verifies() {
        // The boundary belongs to the holder: rejection starts at exp, not before.
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);
        let now = Utc::now().timestamp();

        assert!(
            service
                .verify_token(&forge(secret, now + 1, now, "keyrunes"))
                .is_ok()
        );
    }

    #[test]
    fn a_token_that_expired_this_very_second_is_rejected() {
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);
        let now = Utc::now().timestamp();

        assert!(
            service
                .verify_token(&forge(secret, now, now - 3600, "keyrunes"))
                .is_err(),
            "exp is the first instant at which the token is no longer valid"
        );
    }

    #[test]
    fn a_token_from_another_issuer_is_rejected() {
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);
        let now = Utc::now().timestamp();

        assert!(
            service
                .verify_token(&forge(secret, now + 3600, now, "some-other-service"))
                .is_err(),
            "a token minted by another issuer must not verify here"
        );
    }

    #[test]
    fn an_expired_token_cannot_be_refreshed() {
        // The point of the expiry check: a leaked token must not be able to
        // mint itself a fresh one forever.
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);
        let past = (Utc::now() - Duration::hours(48)).timestamp();
        let expired = forge(secret, past, past - 3600, "keyrunes");

        assert!(service.refresh_token(&expired).is_err());
        assert!(service.extract_user_id(&expired).is_err());
    }

    #[test]
    fn test_extract_user_id() {
        // Setup
        let service = JwtService::new("0123456789ABCDEF0123456789ABCDEF");
        let groups = vec![USERS_GROUP.to_string()];
        let token = service
            .generate_token(42, "test@example.com", "testuser", groups, "test_ns", 1)
            .unwrap();

        // Act
        let user_id = service.extract_user_id(&token).unwrap();

        // Assert
        assert_eq!(user_id, 42);
    }

    // ---------------------------------------------------------------------
    // Exhaustive claim tampering.
    //
    // `verify_token` reads nine claims and every one of them is load-bearing.
    // Rather than sample corruptions, enumerate them: each claim crossed with
    // each way of breaking it must be rejected, with no exceptions.
    // ---------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum ClaimName {
        Sub,
        Email,
        Username,
        Groups,
        Namespace,
        OrganizationId,
        Exp,
        Iat,
        Iss,
    }

    impl ClaimName {
        fn key(self) -> &'static str {
            match self {
                ClaimName::Sub => "sub",
                ClaimName::Email => "email",
                ClaimName::Username => "username",
                ClaimName::Groups => "groups",
                ClaimName::Namespace => "namespace",
                ClaimName::OrganizationId => "organization_id",
                ClaimName::Exp => "exp",
                ClaimName::Iat => "iat",
                ClaimName::Iss => "iss",
            }
        }

        /// A value of the wrong JSON type for this claim.
        fn wrong_type(self) -> Value {
            match self {
                // These are read with `as_str`, so anything but a string breaks.
                ClaimName::Sub
                | ClaimName::Email
                | ClaimName::Username
                | ClaimName::Namespace
                | ClaimName::Iss => Value::Number(7.into()),
                // Read with `as_i64`.
                ClaimName::OrganizationId | ClaimName::Exp | ClaimName::Iat => {
                    Value::String("not-a-number".into())
                }
                // Deserialized into Vec<String>.
                ClaimName::Groups => Value::String("users".into()),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum Tampering {
        /// Drop the claim entirely.
        Remove,
        /// Keep the claim but give it a value of the wrong type.
        WrongType,
        /// Keep the claim but set it to JSON null.
        Null,
    }

    /// The claim set a healthy token carries, as JSON.
    fn healthy_claims() -> serde_json::Map<String, Value> {
        let now = Utc::now().timestamp();
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), Value::String("1".into()));
        claims.insert("email".into(), Value::String("test@example.com".into()));
        claims.insert("username".into(), Value::String("testuser".into()));
        claims.insert("groups".into(), serde_json::json!([USERS_GROUP]));
        claims.insert("namespace".into(), Value::String("test_ns".into()));
        claims.insert("organization_id".into(), Value::Number(1.into()));
        claims.insert("exp".into(), Value::Number((now + 3600).into()));
        claims.insert("iat".into(), Value::Number(now.into()));
        claims.insert("iss".into(), Value::String("keyrunes".into()));
        claims
    }

    /// Sign an arbitrary claim set with `secret`, assembling the JWT by hand.
    ///
    /// `JwtPayload::set_claim` enforces the registered-claim types itself — it
    /// refuses a non-string `sub`, for instance — so building through it can
    /// only produce tokens josekit was willing to make. An attacker is under
    /// no such constraint: they post whatever bytes they like. Encoding the
    /// segments directly is what lets the corruption cases below reach
    /// `verify_token` at all.
    fn sign(secret: &str, claims: serde_json::Map<String, Value>) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let header = B64.encode(br#"{"typ":"JWT","alg":"HS256"}"#);
        let payload = B64.encode(serde_json::to_vec(&Value::Object(claims)).unwrap());
        let message = format!("{header}.{payload}");

        let signer = HS256.signer_from_bytes(secret.as_bytes()).unwrap();
        let signature = signer.sign(message.as_bytes()).unwrap();

        format!("{message}.{}", B64.encode(signature))
    }

    /// The control: an untampered token verifies and round-trips.
    #[test]
    fn the_healthy_claim_set_verifies() {
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);

        let claims = service
            .verify_token(&sign(secret, healthy_claims()))
            .expect("the untampered control token must verify");

        assert_eq!(claims.sub, "1");
        assert_eq!(claims.iss, "keyrunes");
    }

    /// All 9 x 3 single-claim corruptions, each correctly signed. A valid
    /// signature over an invalid claim set must still be refused.
    #[exhaustive_test]
    fn every_single_claim_corruption_is_rejected(claim: ClaimName, how: Tampering) {
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);

        let mut claims = healthy_claims();
        match how {
            Tampering::Remove => {
                claims.remove(claim.key());
            }
            Tampering::WrongType => {
                claims.insert(claim.key().into(), claim.wrong_type());
            }
            Tampering::Null => {
                claims.insert(claim.key().into(), Value::Null);
            }
        }

        assert!(
            service.verify_token(&sign(secret, claims)).is_err(),
            "a token with {claim:?} {how:?} was accepted"
        );
    }

    /// The same corruptions must not panic on the derived operations either.
    #[exhaustive_test]
    fn derived_operations_reject_every_corruption(claim: ClaimName, how: Tampering) {
        let secret = "0123456789ABCDEF0123456789ABCDEF";
        let service = JwtService::new(secret);

        let mut claims = healthy_claims();
        match how {
            Tampering::Remove => {
                claims.remove(claim.key());
            }
            Tampering::WrongType => {
                claims.insert(claim.key().into(), claim.wrong_type());
            }
            Tampering::Null => {
                claims.insert(claim.key().into(), Value::Null);
            }
        }
        let token = sign(secret, claims);

        assert!(service.refresh_token(&token).is_err());
        assert!(service.extract_user_id(&token).is_err());
    }
}
