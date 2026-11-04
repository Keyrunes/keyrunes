use serde::{Deserialize, Deserializer};

/// Deserialize an `i64` sent either as a JSON number (`2`) or as a string
/// (`"2"`): HTML form bodies submit every field as a string, while JSON
/// clients send real numbers, and both must land on the same field.
pub fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i64),
    }

    match StringOrInt::deserialize(deserializer)? {
        StringOrInt::String(s) => s.parse().map_err(serde::de::Error::custom),
        StringOrInt::Int(i) => Ok(i),
    }
}

/// Deserialize a `bool` sent either as `true`/`false` or as the form strings
/// `true|1|on` (truthy) and `false|0|off|""` (falsy).
pub fn deserialize_string_or_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrBool {
        String(String),
        Bool(bool),
    }

    match StringOrBool::deserialize(deserializer)? {
        StringOrBool::String(s) => match s.to_lowercase().as_str() {
            "true" | "1" | "on" => Ok(true),
            "false" | "0" | "off" | "" => Ok(false),
            _ => Err(serde::de::Error::custom(format!("invalid boolean: {}", s))),
        },
        StringOrBool::Bool(b) => Ok(b),
    }
}

/// Optional variant of [`deserialize_string_or_number`]: a present field must
/// parse as `i64` (number or numeric string); an absent or empty one yields
/// `None`.
pub fn deserialize_option_string_or_number<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i64),
    }

    let v: Option<StringOrInt> = Option::deserialize(deserializer)?;

    match v {
        Some(StringOrInt::String(s)) => {
            if s.is_empty() {
                Ok(None)
            } else {
                s.parse().map(Some).map_err(serde::de::Error::custom)
            }
        }
        Some(StringOrInt::Int(i)) => Ok(Some(i)),
        None => Ok(None),
    }
}
