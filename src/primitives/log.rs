use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogType {
    Success,
    Info,
    Error,
    FinalError,
    Warning,
    Hint,
    DebugData,
    Arrow,
    File,
    Link,
    Signature,
    Timestamp,
    Form,
    Scalar,
    Empty,
    Tree,
}

impl LogType {
    pub fn emoji(&self) -> &'static str {
        match self {
            LogType::Success => "✅",
            LogType::Info => "✨",
            LogType::Error => "❌",
            LogType::FinalError => "❌",
            LogType::Warning => "🚨",
            LogType::Hint => "💡",
            LogType::DebugData => "🐞",
            LogType::Arrow => "➡️",
            LogType::File => "📄",
            LogType::Link => "🔗",
            LogType::Signature => "🔏",
            LogType::Timestamp => "👀",
            LogType::Form => "📝",
            LogType::Scalar => "⏺️",
            LogType::Tree => "🌿",
            LogType::Empty => "",
        }
    }
}

// For converting to/from string
impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LogType::Success => "success",
            LogType::Info => "info",
            LogType::Error => "error",
            LogType::FinalError => "final_error",
            LogType::Warning => "warning",
            LogType::Hint => "hint",
            LogType::DebugData => "debug_data",
            LogType::Arrow => "arrow",
            LogType::File => "file",
            LogType::Link => "link",
            LogType::Signature => "signature",
            LogType::Timestamp => "timestamp",
            LogType::Form => "form",
            LogType::Scalar => "scalar",
            LogType::Empty => "empty",
            LogType::Tree => "tree",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for LogType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(LogType::Success),
            "info" => Ok(LogType::Info),
            "error" => Ok(LogType::Error),
            "final_error" => Ok(LogType::FinalError),
            "warning" => Ok(LogType::Warning),
            "hint" => Ok(LogType::Hint),
            "debug_data" => Ok(LogType::DebugData),
            "arrow" => Ok(LogType::Arrow),
            "file" => Ok(LogType::File),
            "link" => Ok(LogType::Link),
            "signature" => Ok(LogType::Signature),
            "timestamp" => Ok(LogType::Timestamp),
            "form" => Ok(LogType::Form),
            "scalar" => Ok(LogType::Scalar),
            "empty" => Ok(LogType::Empty),
            "tree" => Ok(LogType::Tree),
            _ => Err(format!("Unknown log type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogData {
    #[serde(rename = "logType")]
    pub log_type: LogType,
    pub log: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,
}

impl LogData {
    pub fn new(log_type: LogType, log: impl Into<String>) -> Self {
        Self {
            log_type,
            log: log.into(),
            ident: None,
        }
    }

    pub fn with_ident(log_type: LogType, log: impl Into<String>, ident: impl Into<String>) -> Self {
        Self {
            log_type,
            log: log.into(),
            ident: Some(ident.into()),
        }
    }

    pub fn format(&self) -> String {
        let emoji = self.log_type.emoji();

        if emoji.is_empty() {
            if let Some(ident) = &self.ident {
                format!("[{}] {}", ident, self.log)
            } else {
                self.log.clone()
            }
        } else if let Some(ident) = &self.ident {
            format!("{} [{}] {}", emoji, ident, self.log)
        } else {
            format!("{} {}", emoji, self.log)
        }
    }

    pub fn display(&self) -> String {
        self.format()
    }
}
