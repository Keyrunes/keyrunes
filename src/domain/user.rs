use std::fmt;

use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// Validates an e-mail address (`local@domain.tld`) at the type boundary.
#[derive(Debug, Clone)]
pub struct Email(String);

impl TryFrom<&str> for Email {
    type Error = anyhow::Error;

    /// Accepts the shape `^[\w.+-]+@[\w-]+\.[\w.-]+$` and stores the address
    /// verbatim; anything else is rejected.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > crate::constants::MAX_EMAIL_LENGTH {
            anyhow::bail!("email too long");
        }
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        if !email_re.is_match(value) {
            anyhow::bail!("invalid email");
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let email = String::deserialize(deserializer)?;
        Self::try_from(email.as_str()).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// A password held in a [`SecretString`] so it is zeroed on drop and never
/// printed by `Debug`.
#[derive(Debug, Clone)]
pub struct Password(SecretString);

impl TryFrom<&str> for Password {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() < crate::constants::MIN_PASSWORD_LENGTH {
            anyhow::bail!("password too short");
        }
        if value.len() > crate::constants::MAX_PASSWORD_LENGTH {
            anyhow::bail!("password too long");
        }

        Ok(Self(SecretString::from(value)))
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let password = String::deserialize(deserializer)?;

        Ok(Self::try_from(password.as_str()).map_err(|e| serde::de::Error::custom(e.to_string())))?
    }
}

impl Password {
    /// Reveal the plain-text password to hashing/verification call sites.
    ///
    /// The borrow cannot outlive the [`Password`], so the secret is zeroed
    /// with the owner; treat the returned slice as sensitive.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}
