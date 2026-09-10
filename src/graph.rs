//! Print a binary's resolved dependency tree (the `graph` subcommand). Reuses the
//! resolver's transitive resolution, then records each object's direct DT_NEEDED so
//! the parent->child edges can be rendered. A read-only audit view: it stages nothing.

use crate::report::{DepGraphReport, DepNode};
use crate::resolver::{self, Sysroot};
use anyhow::{Context, Result};
use std::path::Path;

/// Resolve `binary` against the host root (honoring `--include` like `pack`) and build
/// its dependency graph: one node per resolved object, each carrying its direct deps.
pub fn build(binary: &Path, includes: &[String]) -> Result<DepGraphReport> {
    let resolution = resolver::resolve_with_includes(binary, &Sysroot::new("/"), includes)?;

    // The binary's own direct deps, plus the --include additions the resolver treats as
    // direct deps of the binary, so the root shows exactly what `pack` would stage.
    let mut root_needed = resolver::read_elf_info(binary)
        .with_context(|| format!("reading {}", binary.display()))?
        .needed;
    root_needed.extend(includes.iter().cloned());

    let mut nodes = Vec::with_capacity(resolution.libs.len() + 1);
    nodes.push(DepNode {
        name: file_name(binary),
        path: binary.display().to_string(),
        needs: dedup(root_needed),
    });
    // Each resolved lib's own direct deps. A file that will not parse is a leaf, matching
    // how the resolver treats it (it keeps such a file but walks no further).
    for lib in &resolution.libs {
        let needs = resolver::read_elf_info(&lib.path)
            .map(|i| i.needed)
            .unwrap_or_default();
        nodes.push(DepNode {
            name: lib.soname.clone(),
            path: lib.path.display().to_string(),
            needs: dedup(needs),
        });
    }

    Ok(DepGraphReport {
        root: file_name(binary),
        interpreter: resolution
            .interpreter
            .as_ref()
            .map(|i| i.image_path.display().to_string()),
        nodes,
        missing: resolution.missing,
    })
}

// The final path component as a String; the whole path when it has none.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

// Drop repeated sonames while keeping first-seen order — DT_NEEDED can list a soname
// twice, and a duplicated edge only clutters the tree.
fn dedup(sonames: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    sonames
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_first_seen_order() {
        let out = dedup(vec![
            "libc.so.6".into(),
            "libm.so.6".into(),
            "libc.so.6".into(),
        ]);
        assert_eq!(out, vec!["libc.so.6".to_string(), "libm.so.6".to_string()]);
    }

    #[test]
    fn file_name_falls_back_to_full_path() {
        assert_eq!(file_name(Path::new("/usr/bin/id")), "id");
    }
}
