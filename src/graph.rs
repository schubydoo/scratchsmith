//! Print a binary's resolved dependency tree (the `graph` subcommand). Reuses the
//! resolver's transitive resolution and its recorded parent->child edges. A read-only
//! audit view: it stages nothing.

use crate::report::{DepGraphReport, DepNode};
use crate::resolver::{self, push_unique, Resolution, Sysroot};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Resolve `binary` against the host root (honoring `--include` like `pack`) and build
/// its dependency graph: one node per resolved object, keyed by real path, with edges
/// pointing at real paths. Keying by path (not soname) means every edge resolves to a
/// node and two objects never collide on one key.
pub fn build(binary: &Path, includes: &[String]) -> Result<DepGraphReport> {
    let resolution = resolver::resolve_with_includes(binary, &Sysroot::new("/"), includes)?;
    resolution.print_hints();
    Ok(report(binary, resolution))
}

// The graph of one resolution, split from `build` so a test can feed a resolution by hand.
fn report(binary: &Path, resolution: Resolution) -> DepGraphReport {
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
    // musl's loader is also its libc, which the binary and its libraries need by name, and it
    // is staged only as the interpreter. Give it a node so those edges do not dangle.
    if let (Some(_), Some(interp)) = (&resolution.musl, &resolution.interpreter) {
        if resolution
            .edges
            .iter()
            .any(|e| e.to.as_ref() == Some(&interp.source))
        {
            name_by_id
                .entry(interp.source.display().to_string())
                .or_insert_with(|| file_name(&interp.image_path));
        }
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

    DepGraphReport {
        root: root_id,
        interpreter: resolution.interpreter_path(),
        nodes,
        missing: resolution.missing,
    }
}

/// Fail loudly when the graph has unresolved dependencies, so a text-mode CI gate
/// (`scratchsmith graph app`) does not pass on an image that could not be built. Callers
/// print the report first, then call this for the exit code.
pub fn check_complete(report: &DepGraphReport) -> Result<()> {
    if report.missing.is_empty() {
        Ok(())
    } else {
        bail!(
            "unresolved dependencies: {}",
            resolver::missing_for_display(&report.missing)
        );
    }
}

// The final path component as a String; the whole path when it has none.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
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

    // The loader gets a node only in a musl resolution with an edge to it. A glibc resolution
    // never has one, so its graph is unchanged.
    #[test]
    fn the_musl_loader_gets_a_node_only_when_an_edge_lands_on_it() {
        use crate::resolver::{DepEdge, MuslSearch, ResolvedInterp, ResolvedLib};
        use std::path::PathBuf;
        let loader = PathBuf::from("/lib/ld-musl-x86_64.so.1");
        let lib = PathBuf::from("/usr/lib/libz.so.1.3");
        let bin = Path::new("/nonexistent/app");
        let edge = |from: &Path, soname: &str, to: &Path| DepEdge {
            from: from.to_path_buf(),
            soname: soname.into(),
            to: Some(to.to_path_buf()),
        };
        let resolution = |musl: bool, edges: Vec<DepEdge>| Resolution {
            interpreter: Some(ResolvedInterp {
                image_path: loader.clone(),
                source: loader.clone(),
            }),
            libs: vec![ResolvedLib {
                soname: "libz.so.1".into(),
                path: lib.clone(),
            }],
            edges,
            musl: musl.then(MuslSearch::default),
            ..Resolution::default()
        };
        let both = vec![
            edge(bin, "libz.so.1", &lib),
            edge(bin, "libc.musl-x86_64.so.1", &loader),
            edge(&lib, "libc.musl-x86_64.so.1", &loader),
        ];
        let graph = report(bin, resolution(true, both.clone()));
        let names: Vec<_> = graph.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["app", "ld-musl-x86_64.so.1", "libz.so.1"]);
        let loader_id = loader.display().to_string();
        assert!(graph.nodes[0].needs.contains(&loader_id));
        assert_eq!(graph.nodes[2].needs, [loader_id]);

        // No edge to the loader, or not musl: no loader node.
        let graph = report(bin, resolution(true, vec![edge(bin, "libz.so.1", &lib)]));
        assert_eq!(graph.nodes.len(), 2);
        let graph = report(bin, resolution(false, both));
        assert!(graph.nodes.iter().all(|n| n.name != "ld-musl-x86_64.so.1"));
    }

    // A musl binary needs its libc, which is the loader. The graph lists the loader as a node.
    #[test]
    fn a_musl_binary_s_libc_edge_lands_on_the_loader_node() {
        if std::process::Command::new("musl-gcc")
            .arg("--version")
            .output()
            .is_err()
        {
            crate::test_support::skip_optional("musl-gcc is not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("m.c");
        std::fs::write(&src, "int main(void){return 0;}\n").unwrap();
        let exe = tmp.path().join("m");
        let built = std::process::Command::new("musl-gcc")
            .arg("-o")
            .arg(&exe)
            .arg(&src)
            .status()
            .unwrap();
        assert!(built.success());
        let report = build(&exe, &[]).unwrap();
        let root = &report.nodes[0];
        assert_eq!(root.needs.len(), 1, "{:?}", report.nodes);
        let loader = report
            .nodes
            .iter()
            .find(|n| n.id == root.needs[0])
            .unwrap_or_else(|| panic!("no node for {}: {:?}", root.needs[0], report.nodes));
        assert_eq!(loader.name, "ld-musl-x86_64.so.1");
        assert!(report.missing.is_empty());
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
