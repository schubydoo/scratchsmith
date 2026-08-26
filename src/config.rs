//! Load `scratchsmith.toml`, optionally select a `[profile.<name>]`, and merge with CLI
//! flags (flags win). See Tasks 2.6 and 5.5.

use crate::supplychain::SbomFormat;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A pack configuration read from `scratchsmith.toml`. Every field is optional so a config
/// can set just what it needs; a selected profile layers over the base, and the CLI overrides
/// whatever it also specifies. Covers every *packing* flag (Task 5.5) — the delivery sinks
/// `--oci-archive` / `-n -o` and the display-only `--format` stay CLI-only.
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
    /// Smoke-run the image after building.
    #[serde(default)]
    pub smoke: bool,
    /// Generate an SBOM of the packed rootfs.
    #[serde(default)]
    pub sbom: bool,
    /// SBOM output path (defaults to `sbom.json` when unset).
    #[serde(rename = "sbom-file")]
    pub sbom_file: Option<PathBuf>,
    /// SBOM format (`cyclonedx-json` or `spdx-json`).
    #[serde(rename = "sbom-format")]
    pub sbom_format: Option<SbomFormat>,
    /// Add the TLS CA bundle (`/etc/ssl/certs/ca-certificates.crt`).
    #[serde(default, rename = "ca-certs")]
    pub ca_certs: bool,
    /// Add the resolved local timezone (`/etc/localtime`).
    #[serde(default)]
    pub tz: bool,
    /// Add a minimal init (`tini`) as pid 1.
    #[serde(default)]
    pub init: bool,
    /// Force-stage extra libraries (sonames or paths), e.g. dlopen'd plugins.
    #[serde(default)]
    pub include: Vec<String>,
    /// Sign the pushed image with cosign (needs a push target).
    #[serde(default)]
    pub sign: bool,
    /// Push target registry reference.
    pub push: Option<String>,
    /// Named profiles — `[profile.<name>]` sections that layer over the base config.
    #[serde(default)]
    pub profile: HashMap<String, Config>,
}

impl Config {
    /// Read and parse a config file. A missing file or a syntax error is a clear
    /// error, never a panic.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    /// Layer the named profile over this base config and return the result. Unknown name is a
    /// clear error. Profiles *augment*: booleans OR, `Option`s prefer the profile, non-empty
    /// vectors replace — the same "flags win" semantics the CLI uses over the file, so a
    /// profile adds to the base but cannot unset a base boolean.
    pub fn select_profile(self, name: &str) -> Result<Config> {
        let Some(profile) = self.profile.get(name).cloned() else {
            let mut names: Vec<&String> = self.profile.keys().collect();
            names.sort();
            bail!(
                "unknown --profile '{name}'; defined profiles: {}",
                if names.is_empty() {
                    "(none)".to_string()
                } else {
                    names
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
        };
        Ok(self.layer(profile))
    }

    // Layer `over` on top of `self` (over wins where it sets a value).
    fn layer(self, over: Config) -> Config {
        let vec_or =
            |base: Vec<String>, over: Vec<String>| if over.is_empty() { base } else { over };
        Config {
            binary: over.binary.or(self.binary),
            entrypoint: over.entrypoint.or(self.entrypoint),
            cmd: vec_or(self.cmd, over.cmd),
            env: vec_or(self.env, over.env),
            workdir: over.workdir.or(self.workdir),
            user: over.user.or(self.user),
            strip: self.strip || over.strip,
            upx: self.upx || over.upx,
            smoke: self.smoke || over.smoke,
            sbom: self.sbom || over.sbom,
            sbom_file: over.sbom_file.or(self.sbom_file),
            sbom_format: over.sbom_format.or(self.sbom_format),
            ca_certs: self.ca_certs || over.ca_certs,
            tz: self.tz || over.tz,
            init: self.init || over.init,
            include: vec_or(self.include, over.include),
            sign: self.sign || over.sign,
            push: over.push.or(self.push),
            profile: self.profile, // the effective config no longer carries nested profiles
        }
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
            smoke = true
            sbom = true
            sbom-file = "out.json"
            sbom-format = "spdx-json"
            ca-certs = true
            tz = true
            init = true
            include = ["libfoo.so"]
            sign = true
            push = "ghcr.io/me/tool:latest"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.binary, Some(PathBuf::from("/usr/bin/tool")));
        assert_eq!(cfg.cmd, vec!["--serve".to_string()]);
        assert!(cfg.strip && cfg.upx && cfg.smoke && cfg.sbom && cfg.sign);
        assert_eq!(cfg.sbom_file, Some(PathBuf::from("out.json")));
        assert_eq!(cfg.sbom_format, Some(SbomFormat::SpdxJson));
        assert!(cfg.ca_certs && cfg.tz && cfg.init);
        assert_eq!(cfg.include, vec!["libfoo.so".to_string()]);
        assert_eq!(cfg.push.as_deref(), Some("ghcr.io/me/tool:latest"));
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

    #[test]
    fn a_profile_layers_over_the_base() {
        let base: Config = toml::from_str(
            r#"
            binary = "/usr/bin/app"
            [profile.ci]
            strip = true
            sbom = true
            sign = true
            push = "ghcr.io/me/app:latest"
        "#,
        )
        .unwrap();
        let ci = base.clone().select_profile("ci").unwrap();
        // Profile options apply...
        assert!(ci.strip && ci.sbom && ci.sign);
        assert_eq!(ci.push.as_deref(), Some("ghcr.io/me/app:latest"));
        // ...and the base carries through (binary was only set at the top level).
        assert_eq!(ci.binary, Some(PathBuf::from("/usr/bin/app")));
        // The base config itself is unchanged without a profile.
        assert!(!base.strip);
    }

    #[test]
    fn unknown_profile_is_a_clear_error() {
        let cfg: Config = toml::from_str("[profile.ci]\nstrip = true\n").unwrap();
        let err = cfg.select_profile("prod").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("prod") && msg.contains("ci"), "got: {msg}");
        // With no profiles defined at all, the message says so rather than listing nothing.
        let err = Config::default().select_profile("prod").unwrap_err();
        assert!(err.to_string().contains("(none)"), "got: {err}");
    }
}
