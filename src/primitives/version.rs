use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt::Display, str::FromStr};

#[derive(SerializeDisplay, DeserializeFromStr, PartialEq, Eq, Hash, Clone, Debug)]
pub enum Version {
    V4,
}

impl Default for Version {
    fn default() -> Self {
        Self::V4
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::V4 => "https://aqua-protocol.org/docs/v4/schema",
            }
        )
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid Version")]
pub struct ParseError;

impl FromStr for Version {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https://aqua-protocol.org/docs/v4/schema" => Ok(Self::V4),
            _ => Err(ParseError),
        }
    }
}
