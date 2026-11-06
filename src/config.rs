use std::{path::{Path, PathBuf}, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(default)]
pub struct Config {
    pub log_level: String,
    pub stdin: bool,
    pub join_commands: Vec<String>,
    pub join_commands_delay_secs: u64,
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub reconnect: ReconnectConfig,
    pub resource_pack: ResourcePackConfig,
    pub chat: ChatConfig,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub cache_path: PathBuf,
    pub client_id: String,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct ReconnectConfig {
    pub backoff_secs: Vec<u64>,
    pub stable_after_secs: u64,
    pub fatal_kick_patterns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct ResourcePackConfig {
    pub accept: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ChatConfig {
    pub rules: Vec<ChatRule>,
}

#[derive(Deserialize)]
pub struct ChatRule {
    pub pattern: String,
    pub reply: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_cooldown() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
    }
}

impl ReconnectConfig {
    pub fn delay(&self, attempt: usize) -> Duration {
        let secs = self.backoff_secs.get(attempt).or(self.backoff_secs.last()).copied().unwrap_or(30);
        Duration::from_secs(secs)
    }

    pub fn is_fatal(&self, reason: &str) -> bool {
        let reason = reason.to_lowercase();
        self.fatal_kick_patterns.iter().any(|pattern| reason.contains(&pattern.to_lowercase()))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            stdin: true,
            join_commands: Vec::new(),
            join_commands_delay_secs: 10,
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            reconnect: ReconnectConfig::default(),
            resource_pack: ResourcePackConfig::default(),
            chat: ChatConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { host: "mc.hypixel.net".into(), port: 25565 }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self { cache_path: "token.json".into(), client_id: "00000000402b5328".into() }
    }
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            backoff_secs: vec![5, 10, 30, 60],
            stable_after_secs: 120,
            fatal_kick_patterns: vec!["logged in from another location".into(), "banned".into()],
        }
    }
}

impl Default for ResourcePackConfig {
    fn default() -> Self {
        Self { accept: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let config: Config = toml::from_str(include_str!("../config.toml")).unwrap();
        assert_eq!(config.server.host, "mc.hypixel.net");
        assert_eq!(config.join_commands, ["/limbo"]);
    }

    #[test]
    fn backoff_caps_at_last_value() {
        let reconnect = ReconnectConfig::default();
        assert_eq!(reconnect.delay(0), Duration::from_secs(5));
        assert_eq!(reconnect.delay(3), Duration::from_secs(60));
        assert_eq!(reconnect.delay(50), Duration::from_secs(60));
    }

    #[test]
    fn fatal_patterns_ignore_case() {
        let reconnect = ReconnectConfig::default();
        assert!(reconnect.is_fatal("You logged in from another location"));
        assert!(!reconnect.is_fatal("Timed out"));
    }
}
