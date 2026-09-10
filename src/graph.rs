//! Print a binary's resolved dependency tree (the `graph` subcommand). Reuses the
//! resolver's transitive resolution and its recorded parent->child edges. A read-only
//! audit view: it stages nothing.

use crate::report::{DepGraphReport, DepNode};
use crate::resolver::{self, Sysroot};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Resolve `binary` against the host root (honoring `--include` like `pack`) and build
/// its dependency graph: one node per resolved object, keyed by real path, with edges
/// pointing at real paths. Keying by path (not soname) means every edge resolves to a
/// node and two objects never collide on one key.
pub fn build(binary: &Path, includes: &[String]) -> Result<DepGraphReport> {
    let resolution = resolver::resolve_with_includes(binary, &Sysroot::new("/"), includes)?;

    // The resolver canonicalizes the binary; its edges' `from` uses that path, so match it.
    let root_id = std::fs::canonicalize(binary)
        .unwrap_or_else(|_| binary.to_path_buf())
        .display()
        .to_string();

    // Display name per object id: the binary's file name for the root, else the soname the
    // loader searched for (the name it is staged under).
    let mut name_by_id: BTreeMap<String, String> = BTreeMap::new();
    name_by_id.insert(root_id.clone(), file_name(binary));
    for lib in &resolution.libs {
        name_by_id
            .entry(lib.path.display().to_string())
            .or_insert_with(|| lib.soname.clone());
    }

    // Group edges by parent: resolved children become `needs` (child ids), unresolved
    // sonames become that node's `missing`.
    let mut needs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut missing_by: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in &resolution.edges {
        let from = e.from.display().to_string();
        match &e.to {
            Some(to) => push_unique(needs.entry(from).or_default(), to.display().to_string()),
            None => push_unique(missing_by.entry(from).or_default(), e.soname.clone()),
        }
    }

    let mut nodes: Vec<DepNode> = name_by_id
        .into_iter()
        .map(|(id, name)| DepNode {
            needs: needs.remove(&id).unwrap_or_default(),
            missing: missing_by.remove(&id).unwrap_or_default(),
            name,
            id,
        })
        .collect();
    // Root first, then the rest by id — a stable, testable order.
    nodes.sort_by(|a, b| (a.id != root_id, &a.id).cmp(&(b.id != root_id, &b.id)));

    Ok(DepGraphReport {
        root: root_id,
        interpreter: resolution
            .interpreter
            .as_ref()
            .map(|i| i.image_path.display().to_string()),
        nodes,
        missing: resolution.missing,
    })
}

/// Fail loudly when the graph has unresolved dependencies, so a text-mode CI gate
/// (`scratchsmith graph app`) does not pass on an image that could not be built. Callers
/// print the report first, then call this for the exit code.
pub fn check_complete(report: &DepGraphReport) -> Result<()> {
    if report.missing.is_empty() {
        Ok(())
    } else {
        bail!("unresolved dependencies: {}", report.missing.join(", "));
    }
}

// The final path component as a String; the whole path when it has none.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

// Append `item` to `v` unless already present (a parent can list a soname twice).
fn push_unique(v: &mut Vec<String>, item: String) {
    if !v.contains(&item) {
        v.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_unique_drops_repeats() {
        let mut v = Vec::new();
        push_unique(&mut v, "a".into());
        push_unique(&mut v, "b".into());
        push_unique(&mut v, "a".into());
        assert_eq!(v, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn file_name_falls_back_to_full_path() {
        assert_eq!(file_name(Path::new("/usr/bin/id")), "id");
    }

    #[test]
    fn check_complete_fails_only_when_missing() {
        let mut report = DepGraphReport {
            root: "/app".into(),
            interpreter: None,
            nodes: vec![],
            missing: vec![],
        };
        assert!(check_complete(&report).is_ok());
        report.missing = vec!["libx.so".into()];
        let err = check_complete(&report).unwrap_err();
        assert!(err.to_string().contains("libx.so"), "{err}");
    }
}
