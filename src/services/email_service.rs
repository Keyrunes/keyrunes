use anyhow::{Context, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use std::sync::Arc;
use tera::Tera;

/// Service for sending emails via SMTP
#[derive(Clone)]
pub struct EmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_host: String,
    smtp_port: u16,
    from_email: String,
    from_name: String,
    frontend_url: String,
    tera: Arc<Tera>,
}

impl EmailService {
    /// Create a new EmailService from environment variables
    pub fn from_env(tera: Arc<Tera>) -> Result<Self> {
        let smtp_username =
            std::env::var("SMTP_USERNAME").context("SMTP_USERNAME not set in environment")?;
        let smtp_password =
            std::env::var("SMTP_PASSWORD").context("SMTP_PASSWORD not set in environment")?;
        let smtp_host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".to_string());
        let smtp_port = std::env::var("SMTP_PORT")
            .unwrap_or_else(|_| "587".to_string())
            .parse::<u16>()
            .context("Invalid SMTP_PORT")?;
        let from_email = std::env::var("FROM_EMAIL").unwrap_or_else(|_| smtp_username.clone());
        let from_name = std::env::var("FROM_NAME").unwrap_or_else(|_| "KeyRunes".to_string());
        let frontend_url =
            std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        Ok(Self {
            smtp_username,
            smtp_password,
            smtp_host,
            smtp_port,
            from_email,
            from_name,
            frontend_url,
            tera,
        })
    }

    /// Send a password reset email
    pub async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<()> {
        let reset_url = format!(
            "{}/reset-password?forgot_password={}",
            self.frontend_url, reset_token
        );

        let mut context = tera::Context::new();
        context.insert("reset_url", &reset_url);

        let html_body = self
            .tera
            .render("mail/password_reset.html", &context)
            .context("Failed to render email template")?;

        let email = Message::builder()
            .from(format!("{} <{}>", self.from_name, self.from_email).parse()?)
            .to(to_email.parse()?)
            .subject("Password Reset - Keyrunes")
            .header(ContentType::TEXT_HTML)
            .body(html_body)?;

        let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

        let mailer: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)?
                .credentials(creds)
                .port(self.smtp_port)
                .build();

        mailer.send(email).await.context("Failed to send email")?;

        tracing::info!("Password reset email sent to {}", to_email);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn create_test_tera() -> Arc<Tera> {
        let mut tera = Tera::new();
        tera.load_from_glob("templates/**/*")
            .expect("Failed to load templates");
        Arc::new(tera)
    }

    #[test]
    #[serial]
    fn test_email_service_from_env_missing_required() {
        let tera = create_test_tera();

        unsafe {
            std::env::remove_var("SMTP_USERNAME");
            std::env::remove_var("SMTP_PASSWORD");
        }

        let result = EmailService::from_env(tera);
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_email_service_from_env_with_defaults() {
        let tera = create_test_tera();

        unsafe {
            std::env::set_var("SMTP_USERNAME", "test@example.com");
            std::env::set_var("SMTP_PASSWORD", "password");
        }

        let service = EmailService::from_env(tera).unwrap();

        assert_eq!(service.smtp_host, "smtp.gmail.com");
        assert_eq!(service.smtp_port, 587);
        assert_eq!(service.from_name, "KeyRunes");
        assert_eq!(service.frontend_url, "http://localhost:3000");

        unsafe {
            std::env::remove_var("SMTP_USERNAME");
            std::env::remove_var("SMTP_PASSWORD");
        }
    }
}
