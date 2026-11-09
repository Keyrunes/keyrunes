use std::time::Duration;

use serde::Deserialize;

/// Google reCAPTCHA siteverify endpoint. Hard-coded in production to avoid
/// an SSRF knob; tests override it through [`RecaptchaVerifier::with_siteverify_url`].
const DEFAULT_SITEVERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

/// Verifies reCAPTCHA tokens against Google's siteverify endpoint.
///
/// The verifier is stateless and cheap to clone: it only carries the secret
/// (and, in tests, an override for the siteverify URL). It performs no I/O
/// until [`Self::verify`] is called.
#[derive(Clone)]
pub struct RecaptchaVerifier {
    secret: String,
    siteverify_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct SiteverifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

impl RecaptchaVerifier {
    /// Build a verifier from the configured secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            siteverify_url: DEFAULT_SITEVERIFY_URL.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
        }
    }

    /// Test-only override for the siteverify URL. Never call this in
    /// production code: it exists so tests can point at a mock server.
    #[cfg(test)]
    pub fn with_siteverify_url(mut self, url: impl Into<String>) -> Self {
        self.siteverify_url = url.into();
        self
    }

    /// Verify a reCAPTCHA response token.
    ///
    /// Fails closed: a network error, a non-2xx status, a malformed body or
    /// an empty token all yield `Err`. Only an explicit `success: true` from
    /// Google yields `Ok(())`.
    pub async fn verify(
        &self,
        response_token: &str,
        remote_ip: Option<&str>,
    ) -> Result<(), String> {
        if response_token.trim().is_empty() {
            return Err("empty recaptcha response".to_string());
        }

        let mut form = vec![
            ("secret", self.secret.as_str()),
            ("response", response_token),
        ];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip));
        }

        let response = self
            .client
            .post(&self.siteverify_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("recaptcha request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!(
                "recaptcha siteverify returned {}",
                response.status()
            ));
        }

        let body: SiteverifyResponse = response
            .json()
            .await
            .map_err(|e| format!("recaptcha response malformed: {e}"))?;

        if body.success {
            Ok(())
        } else {
            Err(format!(
                "recaptcha verification failed: {}",
                body.error_codes.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn verify_success() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success": true}"#)
            .create_async()
            .await;

        let verifier = RecaptchaVerifier::new("secret").with_siteverify_url(server.url());
        assert!(verifier.verify("good-token", None).await.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn verify_failure() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success": false, "error-codes": ["invalid-input-response"]}"#)
            .create_async()
            .await;

        let verifier = RecaptchaVerifier::new("secret").with_siteverify_url(server.url());
        let err = verifier.verify("bad-token", None).await.unwrap_err();
        assert!(err.contains("recaptcha verification failed"));
    }

    #[tokio::test]
    async fn verify_http_error_fails_closed() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .create_async()
            .await;

        let verifier = RecaptchaVerifier::new("secret").with_siteverify_url(server.url());
        assert!(verifier.verify("token", None).await.is_err());
    }

    #[tokio::test]
    async fn verify_malformed_body_fails_closed() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not json")
            .create_async()
            .await;

        let verifier = RecaptchaVerifier::new("secret").with_siteverify_url(server.url());
        assert!(verifier.verify("token", None).await.is_err());
    }

    #[tokio::test]
    async fn empty_token_rejected_before_network() {
        let verifier = RecaptchaVerifier::new("secret");
        let err = verifier.verify("", None).await.unwrap_err();
        assert!(err.contains("empty recaptcha response"));
    }
}
