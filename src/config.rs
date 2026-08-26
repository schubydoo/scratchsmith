//! Load `scratchsmith.toml` and merge it with CLI flags (flags win). See Task 2.6.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// A pack configuration read from `scratchsmith.toml`. Every field is optional so a
/// config can set just what it needs; the CLI overrides whatever it also specifies.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)] // an unknown key is a typo, not a silent no-op
pub struct Config {
    /// The binary to pack, if not given on the command line.
    pub binary: Option<PathBuf>,
    /// Image entrypoint override.
    pub entrypoint: Option<String>,
    /// Default arguments (`Cmd`).
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Environment entries `KEY=VALUE`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory.
    pub workdir: Option<String>,
    /// Image user `UID[:GID]`.
    pub user: Option<String>,
    /// Strip symbols during pack.
    #[serde(default)]
    pub strip: bool,
    /// Compress the packed binary with UPX.
    #[serde(default)]
    pub upx: bool,
}

impl Config {
    /// Read and parse a config file. A missing file or a syntax error is a clear
    /// error, never a panic.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_config() {
        let cfg: Config = toml::from_str(
            r#"
            binary = "/usr/bin/tool"
            entrypoint = "/usr/bin/tool"
            cmd = ["--serve"]
            env = ["FOO=bar"]
            workdir = "/work"
            user = "1000:1000"
            strip = true
            upx = true
        "#,
        )
        .unwrap();
        assert_eq!(cfg.binary, Some(PathBuf::from("/usr/bin/tool")));
        assert_eq!(cfg.cmd, vec!["--serve".to_string()]);
        assert!(cfg.strip);
        assert!(cfg.upx);
    }

    #[test]
    fn empty_config_is_all_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("bogus_key = 1").unwrap_err();
        assert!(err.to_string().contains("bogus_key") || err.to_string().contains("unknown"));
    }

    #[test]
    fn missing_file_is_a_clear_error() {
        let err = Config::load(Path::new("/nonexistent/scratchsmith.toml")).unwrap_err();
        assert!(err.to_string().contains("reading config"));
    }
}
