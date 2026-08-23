//! TOML configuration for the sandbox (`claude-aegis.toml`).
//!
//! Loaded by `claude-aegis run`; scaffolded by `claude-aegis init`. The schema
//! maps one-to-one onto [`crate::SandboxConfig`] (see `Config::into_sandbox`).

use serde::Deserialize;
use std::path::Path;

/// A parsed `claude-aegis.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// AppContainer profile name (identity). Default `"claude-aegis"`.
    pub profile: String,
    /// Program to sandbox: a bare name (resolved from PATH) or a full path.
    pub command: String,
    /// File-system grants.
    pub files: Files,
    /// Network domain allow-list.
    pub network: Network,
    /// Process allow-list.
    pub process: Process,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            profile: "claude-aegis".to_string(),
            command: "claude".to_string(),
            files: Files::default(),
            network: Network::default(),
            process: Process::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Files {
    /// Directories the sandbox may read (and traverse).
    pub read: Vec<String>,
    /// Directories the sandbox may write (implies read).
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Network {
    /// Domains the sandbox may reach, enforced by the loopback proxy.
    /// Empty means no domain filter (network governed by capabilities only).
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Process {
    /// Executable paths the sandbox may launch. Empty means "allow all".
    pub allow: Vec<String>,
}

impl Config {
    /// The default file name the CLI looks for.
    pub const FILE_NAME: &'static str = "claude-aegis.toml";

    /// Load and parse a TOML config file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&text).map_err(ConfigError::Toml)
    }

    /// A starter template, written by `claude-aegis init`.
    pub fn template() -> &'static str {
        r#"# claude-aegis sandbox configuration
# `claude-aegis run` launches `command` inside an AppContainer sandbox.

# AppContainer profile name (identity). Default: claude-aegis.
profile = "claude-aegis"

# Program to sandbox: a bare name (resolved from PATH) or a full path.
command = "claude"

[files]
# Directories the sandbox may READ (and traverse). Everything else is hidden.
read = []
# Directories the sandbox may WRITE (implies read).
write = []

[network]
# Domains the sandbox may reach, via a loopback proxy. Empty = no domain filter.
domains = ["anthropic.com"]

[process]
# Executable paths the sandbox may launch. Empty = allow all.
allow = []
"#
    }
}

/// Errors from loading or parsing a config file.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "{e}"),
            ConfigError::Toml(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}
