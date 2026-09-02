//! JavaScript: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`.
//!
//! No YAML dependency. `pnpm-lock.yaml` and `yarn.lock` are parsed structurally
//! from the one section that matters, and both parsers refuse formats they do not
//! recognize rather than returning whatever they managed to scrape. Pulling a
//! full YAML stack in to read one flat map of keys would cost more dependency
//! budget than the whole rest of the crate.

use std::path::Path;

use n3t_core::confidence::Confidence;
use n3t_core::purl::Purl;

use crate::{exec, read, DiscoveredPackage, Ecosystem, Inventory, InventorySource, ParseError};

/// The npm ecosystem (npm, pnpm, yarn).
pub struct Npm;

/// `package-lock.json` versions this parser understands.
const SUPPORTED_NPM_LOCK_VERSIONS: &[u64] = &[1, 2, 3];

impl Ecosystem for Npm {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, root: &Path) -> bool {
        [
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        ]
        .iter()
        .any(|f| root.join(f).exists())
    }

    fn native(&self, root: &Path) -> Option<Result<Inventory, ParseError>> {
        // `npm ls` reads node_modules. Without it there is nothing to report and
        // the lockfile is the better source.
        if !root.join("node_modules").exists() || !exec::available("npm") {
            return None;
        }
        let raw = exec::run("npm", &["ls", "--all", "--json"], root).ok()?;
        Some(Ok(parse_npm_ls(&raw)))
    }

    fn fallback(&self, root: &Path) -> Result<Inventory, ParseError> {
        let mut inv = Inventory::default();

        let npm_lock = root.join("package-lock.json");
        if npm_lock.exists() {
            inv.merge(parse_package_lock(&npm_lock)?);
        }

        let pnpm_lock = root.join("pnpm-lock.yaml");
        if pnpm_lock.exists() {
            inv.merge(parse_pnpm_lock(&pnpm_lock)?);
        }

        let yarn_lock = root.join("yarn.lock");
        if yarn_lock.exists() {
            inv.merge(parse_yarn_lock(&yarn_lock)?);
        }

        if inv.packages.is_empty() && root.join("package.json").exists() {
            inv.gap(
                "npm",
                "package.json present but no lockfile; versions unresolved",
            );
        }

        Ok(inv)
    }
}

/// Split an npm identifier into (scope, name).
fn split_scope(spec: &str) -> (Option<String>, String) {
    match spec.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, name)) => (Some(format!("@{scope}")), name.to_string()),
        None => (None, spec.to_string()),
    }
}

fn push(inv: &mut Inventory, spec: &str, version: &str, direct: bool) {
    let (namespace, name) = split_scope(spec);
    if name.is_empty() || version.is_empty() {
        return;
    }
    if let Ok(purl) = Purl::new("npm", namespace, name, Some(version.to_string())) {
        inv.packages.push(DiscoveredPackage {
            purl,
            confidence: Confidence::High,
            direct,
        });
    }
}

// --- npm ls --json -------------------------------------------------------

fn parse_npm_ls(raw: &str) -> Inventory {
    let mut inv = Inventory::default();
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(root) => {
            if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
                walk_ls_tree(deps, &mut inv, true);
            }
            inv.sources.push(InventorySource::Native {
                tool: "npm ls --all --json".into(),
            });
        }
        Err(e) => inv.gap("npm", format!("npm ls output not understood: {e}")),
    }
    inv
}

fn walk_ls_tree(
    deps: &serde_json::Map<String, serde_json::Value>,
    inv: &mut Inventory,
    direct: bool,
) {
    for (name, node) in deps {
        if let Some(version) = node.get("version").and_then(|v| v.as_str()) {
            push(inv, name, version, direct);
        }
        if let Some(nested) = node.get("dependencies").and_then(|d| d.as_object()) {
            walk_ls_tree(nested, inv, false);
        }
    }
}

// --- package-lock.json ---------------------------------------------------

fn parse_package_lock(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_package_lock_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_package_lock_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ParseError::Unrecognized {
            path: path_label.to_string(),
            detail: format!("invalid JSON: {e}"),
        })?;

    let mut inv = Inventory::default();
    let version = doc.get("lockfileVersion").and_then(|v| v.as_u64());

    if let Some(v) = version {
        if !SUPPORTED_NPM_LOCK_VERSIONS.contains(&v) {
            inv.gap(
                "npm",
                format!("package-lock.json lockfileVersion {v} not supported (known: {SUPPORTED_NPM_LOCK_VERSIONS:?})"),
            );
            return Ok(inv);
        }
    }

    // v2/v3: a flat `packages` map keyed by install path.
    if let Some(packages) = doc.get("packages").and_then(|p| p.as_object()) {
        for (key, node) in packages {
            // "" is the project itself.
            if key.is_empty() {
                continue;
            }
            // Take the segment after the *last* node_modules to get the real
            // identity of a nested duplicate.
            let Some(spec) = key.rsplit_once("node_modules/").map(|(_, s)| s) else {
                continue;
            };
            let Some(version) = node.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let direct = key.matches("node_modules/").count() == 1;
            push(&mut inv, spec, version, direct);
        }
    // v1: a nested `dependencies` tree.
    } else if let Some(deps) = doc.get("dependencies").and_then(|d| d.as_object()) {
        walk_ls_tree(deps, &mut inv, true);
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: version,
    });
    Ok(inv)
}

// --- pnpm-lock.yaml ------------------------------------------------------

/// Parses the `packages:` block only.
///
/// v5: `  /name/1.2.3:`  ·  v6: `  /name@1.2.3:`  ·  v9: `  name@1.2.3:`
fn parse_pnpm_lock(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_pnpm_lock_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_pnpm_lock_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let mut inv = Inventory::default();

    let declared = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("lockfileVersion:"))
        .map(|v| v.trim().trim_matches('\'').trim_matches('"').to_string());

    let major = declared
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse::<u64>().ok());

    if let Some(major) = major {
        if !(5..=9).contains(&major) {
            inv.gap(
                "npm",
                format!("pnpm-lock.yaml lockfileVersion {major} not supported (known: 5-9)"),
            );
            return Ok(inv);
        }
    }

    let mut in_packages = false;
    let mut local_paths = 0usize;
    let mut unrecognized: Vec<String> = Vec::new();
    for line in text.lines() {
        // Blank lines carry no structure and must not close the section. Real
        // pnpm lockfiles put one immediately after `packages:`, and treating it
        // as a top-level key silently yields zero packages from a 500KB file.
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            // `snapshots:` in v9 repeats the same `name@version` keys, so any
            // other top-level key must close the section rather than be ignored.
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Entries are exactly two spaces deep and end in a colon.
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent != 2 || !trimmed.ends_with(':') {
            continue;
        }
        let entry = trimmed
            .trim_end_matches(':')
            .trim_matches('\'')
            .trim_matches('"');

        match classify_pnpm_entry(entry) {
            PnpmEntry::Registry { spec, version } => push(&mut inv, &spec, &version, false),
            PnpmEntry::LocalPath => local_paths += 1,
            PnpmEntry::Unrecognized => unrecognized.push(entry.to_string()),
        }
    }

    // Understood and deliberately excluded: a `file:`/`link:`/`workspace:` entry
    // is a directory in this repo, not a registry package, so it has no advisory
    // identity. Its own third-party dependencies are separately present in this
    // same lockfile and are checked, so excluding it loses no coverage — but it
    // is reported, because silently dropping 109 of 1403 entries is exactly the
    // failure this parser is supposed to make impossible.
    if local_paths > 0 {
        inv.note(format!(
            "{local_paths} local path dependenc(ies) in {} excluded (file:/link:/workspace: \
             have no registry identity; their own dependencies are listed separately)",
            path_label
        ));
    }

    // Neither understood nor excludable. This is a real hole, so it is a gap.
    if !unrecognized.is_empty() {
        let sample: Vec<&str> = unrecognized.iter().take(3).map(String::as_str).collect();
        inv.gap(
            "npm",
            format!(
                "{} entr(ies) in {} not understood (e.g. {}); these were NOT checked",
                unrecognized.len(),
                path_label,
                sample.join(", ")
            ),
        );
    }

    if inv.packages.is_empty() && local_paths == 0 {
        inv.gap("npm", format!("no packages parsed from {}", path_label));
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: major,
    });
    Ok(inv)
}

/// What a `packages:` key turned out to be.
///
/// Three outcomes, not two. Collapsing `LocalPath` and `Unrecognized` into a
/// single "skip" is what let 109 of vite's 1403 entries disappear without a
/// trace: excluding something you understand is a decision, excluding something
/// you don't is a hole, and only the second may be silent about which it was.
#[derive(Debug, PartialEq, Eq)]
enum PnpmEntry {
    /// A registry package with a resolvable version.
    Registry {
        /// Package identifier, scope included.
        spec: String,
        /// Version.
        version: String,
    },
    /// `file:`, `link:`, or `workspace:` — a directory, not a registry package.
    LocalPath,
    /// Shape we do not understand. Becomes a coverage gap.
    Unrecognized,
}

fn classify_pnpm_entry(entry: &str) -> PnpmEntry {
    // Strip peer-dependency suffixes: `foo@1.0.0(bar@2.0.0)`.
    let entry = entry.split('(').next().unwrap_or(entry);
    let entry = entry.strip_prefix('/').unwrap_or(entry);

    // Local path protocols carry no registry identity.
    for proto in ["@file:", "@link:", "@workspace:", "/file:", "/link:"] {
        if entry.contains(proto) {
            return PnpmEntry::LocalPath;
        }
    }

    // v6/v9: rightmost `@` separates version, but not the scope's leading `@`.
    if let Some((spec, version)) = entry.rsplit_once('@') {
        if !spec.is_empty() && version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return PnpmEntry::Registry {
                spec: spec.to_string(),
                version: version.to_string(),
            };
        }
    }
    // v5: `name/1.2.3` or `@scope/name/1.2.3`.
    if let Some((spec, version)) = entry.rsplit_once('/') {
        if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return PnpmEntry::Registry {
                spec: spec.to_string(),
                version: version.to_string(),
            };
        }
    }
    PnpmEntry::Unrecognized
}

// --- yarn.lock -----------------------------------------------------------

/// Handles both classic (v1) and berry.
///
/// Classic:  `"foo@^1.0.0":\n  version "1.2.3"`
/// Berry:    `"foo@npm:^1.0.0":\n  version: 1.2.3`
fn parse_yarn_lock(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_yarn_lock_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_yarn_lock_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let mut inv = Inventory::default();
    let mut pending: Option<String> = None;
    let mut local_paths = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if !line.starts_with(char::is_whitespace) && trimmed.ends_with(':') {
            // An entry header. Multiple specs may share one entry; the first is
            // enough, since they all resolve to the same version.
            let header = trimmed.trim_end_matches(':');
            // Berry's `__metadata:` block also carries a `version:` field, which
            // would otherwise be read as a package named `__metadata`.
            if header.starts_with("__") {
                pending = None;
                continue;
            }
            match header
                .split(',')
                .next()
                .map(|s| s.trim().trim_matches('"').to_string())
                .and_then(|s| yarn_spec_name(&s))
            {
                Some(YarnEntry::Registry(name)) => pending = Some(name),
                Some(YarnEntry::LocalPath) => {
                    local_paths += 1;
                    pending = None;
                }
                None => pending = None,
            }
            continue;
        }

        if let Some(name) = pending.clone() {
            let value = trimmed
                .strip_prefix("version:")
                .or_else(|| trimmed.strip_prefix("version "))
                .map(|v| v.trim().trim_matches('"').to_string());
            if let Some(version) = value {
                push(&mut inv, &name, &version, false);
                pending = None;
            }
        }
    }

    if local_paths > 0 {
        inv.note(format!(
            "{local_paths} local path/workspace entr(ies) in {path_label} excluded \
             (workspace:/file:/link:/portal:/patch: have no registry identity)"
        ));
    }

    if inv.packages.is_empty() && local_paths == 0 {
        inv.gap("npm", format!("no packages parsed from {}", path_label));
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: None,
    });
    Ok(inv)
}

/// What a yarn entry header turned out to be.
#[derive(Debug, PartialEq, Eq)]
enum YarnEntry {
    /// A registry package. `name` is the package's *real* identity.
    Registry(String),
    /// `workspace:`, `file:`, `link:`, `portal:` — a directory, not a package.
    LocalPath,
}

/// Strip a range/protocol suffix from a bare spec: `@scope/name@^1.0.0` → `@scope/name`.
fn plain_name(spec: &str) -> Option<String> {
    let (scope_prefix, rest) = match spec.strip_prefix('@') {
        Some(rest) => ("@", rest),
        None => ("", spec),
    };
    let name = rest.split('@').next()?;
    if name.is_empty() {
        return None;
    }
    Some(format!("{scope_prefix}{name}"))
}

/// Resolve a yarn entry header to the package it actually installs.
///
/// The subtlety is **aliases**. `eslint-v9@npm:eslint@^9.0.0` installs `eslint`
/// under the local name `eslint-v9`; the header's leading token is a local label,
/// not a package. Reading it as a package name invents dependencies that are not
/// installed — and since npm's namespace is full of typosquats, an invented name
/// can collide with a real `MAL-` advisory and produce a **false malicious-package
/// finding**. Both react and babel use aliases, and both produced exactly that.
///
/// Distinguishing the two forms after `@npm:`:
///   - `left-pad@npm:^1.3.0`           → remainder is a bare range → plain entry
///   - `eslint-v9@npm:eslint@^9.0.0`   → remainder holds another `@` → alias
fn yarn_spec_name(spec: &str) -> Option<YarnEntry> {
    for proto in ["@workspace:", "@file:", "@link:", "@portal:", "@patch:"] {
        if spec.contains(proto) {
            return Some(YarnEntry::LocalPath);
        }
    }

    if let Some((_alias, rest)) = spec.split_once("@npm:") {
        // A leading `@` here is a scope, not a separator, so look past it.
        let after_scope = rest.strip_prefix('@').unwrap_or(rest);
        if after_scope.contains('@') {
            return plain_name(rest).map(YarnEntry::Registry);
        }
    }

    plain_name(spec).map(YarnEntry::Registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn tmp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n3t-npm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        path
    }

    fn names(inv: &Inventory) -> Vec<String> {
        let mut v: Vec<_> = inv.packages.iter().map(|p| p.purl.to_string()).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn package_lock_v3_with_scopes() {
        let path = tmp(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{
                "":{"name":"app"},
                "node_modules/left-pad":{"version":"1.3.0"},
                "node_modules/@angular/core":{"version":"17.0.0"},
                "node_modules/foo/node_modules/left-pad":{"version":"1.1.0"}
            }}"#,
        );
        let inv = parse_package_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:npm/%40angular/core@17.0.0",
                "pkg:npm/left-pad@1.1.0",
                "pkg:npm/left-pad@1.3.0",
            ]
        );
    }

    // A nested duplicate at a different version is a distinct package and must
    // not be collapsed into its top-level namesake.
    #[test]
    fn nested_duplicate_versions_are_distinct() {
        let path = tmp(
            "package-lock-dup.json",
            r#"{"lockfileVersion":3,"packages":{
                "node_modules/ms":{"version":"2.1.3"},
                "node_modules/debug/node_modules/ms":{"version":"2.0.0"}
            }}"#,
        );
        let inv = parse_package_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:npm/ms@2.0.0", "pkg:npm/ms@2.1.3"]);
    }

    #[test]
    fn package_lock_v1_nested_tree() {
        let path = tmp(
            "package-lock-v1.json",
            r#"{"lockfileVersion":1,"dependencies":{
                "left-pad":{"version":"1.3.0","dependencies":{"ms":{"version":"2.0.0"}}}
            }}"#,
        );
        let inv = parse_package_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:npm/left-pad@1.3.0", "pkg:npm/ms@2.0.0"]);
    }

    #[test]
    fn unknown_lockfile_version_is_a_gap() {
        let path = tmp(
            "package-lock-future.json",
            r#"{"lockfileVersion":9,"packages":{"node_modules/x":{"version":"1.0.0"}}}"#,
        );
        let inv = parse_package_lock(&path).expect("parse");
        assert!(
            inv.packages.is_empty(),
            "must not half-parse an unknown format"
        );
        assert_eq!(inv.gaps.len(), 1);
    }

    #[test]
    fn pnpm_v9_entries() {
        let path = tmp(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\npackages:\n\
             \x20 left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\
             \x20 '@angular/core@17.0.0':\n    resolution: {integrity: sha512-y}\n\
             \x20 debug@4.3.4(supports-color@8.1.1):\n    resolution: {integrity: sha512-z}\n",
        );
        let inv = parse_pnpm_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:npm/%40angular/core@17.0.0",
                "pkg:npm/debug@4.3.4",
                "pkg:npm/left-pad@1.3.0"
            ]
        );
    }

    // Regression: real pnpm lockfiles put a blank line right after `packages:`,
    // and an earlier version of this parser read that as a top-level key and
    // closed the section, returning zero packages from a 500KB file. Found by
    // the real-world corpus, not by the hand-written fixtures — which is the
    // entire argument for having the corpus.
    #[test]
    fn pnpm_blank_line_after_packages_header() {
        let path = tmp(
            "pnpm-blank.yaml",
            "lockfileVersion: '9.0'\n\n\
             settings:\n  autoInstallPeers: false\n\n\
             importers:\n\n\
             \x20 .:\n    dependencies:\n      vite:\n        specifier: ^5.0.0\n\n\
             packages:\n\n\
             \x20 '@11ty/gray-matter@2.1.0':\n    resolution: {integrity: sha512-x}\n    engines: {node: '>=11'}\n\n\
             \x20 '@adobe/css-tools@4.3.3':\n    resolution: {integrity: sha512-y}\n\n\
             snapshots:\n\n\
             \x20 '@11ty/gray-matter@2.1.0':\n    dependencies: {}\n",
        );
        let inv = parse_pnpm_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:npm/%4011ty/gray-matter@2.1.0",
                "pkg:npm/%40adobe/css-tools@4.3.3"
            ]
        );
        assert!(inv.gaps.is_empty());
    }

    // `snapshots:` repeats the same keys. Counting both would double every
    // package in a v9 lockfile.
    #[test]
    fn pnpm_snapshots_section_is_not_double_counted() {
        let path = tmp(
            "pnpm-snapshots.yaml",
            "lockfileVersion: '9.0'\n\npackages:\n\n\
             \x20 left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\n\
             snapshots:\n\n\
             \x20 left-pad@1.3.0: {}\n",
        );
        let inv = parse_pnpm_lock(&path).expect("parse");
        assert_eq!(
            inv.packages.len(),
            1,
            "snapshots section must not add packages"
        );
    }

    #[test]
    fn pnpm_v5_slash_entries() {
        let path = tmp(
            "pnpm-lock-v5.yaml",
            "lockfileVersion: 5.4\n\npackages:\n\
             \x20 /left-pad/1.3.0:\n    dev: false\n\
             \x20 /@angular/core/17.0.0:\n    dev: false\n",
        );
        let inv = parse_pnpm_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            ["pkg:npm/%40angular/core@17.0.0", "pkg:npm/left-pad@1.3.0"]
        );
    }

    #[test]
    fn pnpm_unknown_version_is_a_gap() {
        let path = tmp(
            "pnpm-future.yaml",
            "lockfileVersion: '42.0'\n\npackages:\n  x@1.0.0:\n",
        );
        let inv = parse_pnpm_lock(&path).expect("parse");
        assert!(inv.packages.is_empty());
        assert_eq!(inv.gaps.len(), 1);
    }

    #[test]
    fn yarn_classic() {
        let path = tmp(
            "yarn.lock",
            "# yarn lockfile v1\n\n\
             left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://x\"\n\n\
             \"@angular/core@^17.0.0\":\n  version \"17.0.0\"\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            ["pkg:npm/%40angular/core@17.0.0", "pkg:npm/left-pad@1.3.0"]
        );
    }

    #[test]
    fn yarn_berry() {
        let path = tmp(
            "yarn-berry.lock",
            "__metadata:\n  version: 8\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n\n\
             \"@angular/core@npm:^17.0.0\":\n  version: 17.0.0\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            ["pkg:npm/%40angular/core@17.0.0", "pkg:npm/left-pad@1.3.0"]
        );
    }

    #[test]
    fn yarn_multi_spec_entry() {
        let path = tmp(
            "yarn-multi.lock",
            "ms@^2.0.0, ms@^2.1.1:\n  version \"2.1.3\"\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:npm/ms@2.1.3"]);
    }

    // Regression, found by differential testing against osv-scanner on real
    // repos: a yarn alias header names a LOCAL label, not a package. Reading it
    // as a package invents a dependency that is not installed — and because npm's
    // namespace is full of typosquats, the invented name collided with a real
    // MAL- advisory and produced a false "malicious package" finding on both
    // react and babel.
    #[test]
    fn yarn_aliases_resolve_to_the_real_package() {
        let path = tmp(
            "yarn-alias.lock",
            "__metadata:\n  version: 8\n\n\
             \"npm-babel-parser@npm:@babel/parser@^7.14.0\":\n  version: 7.29.3\n               resolution: \"@babel/parser@npm:7.29.3\"\n\n\
             \"eslint-v9@npm:eslint@^9.0.0\":\n  version: 9.0.0\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n\n\
             \"@babel/core@npm:^7.0.0\":\n  version: 7.24.0\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:npm/%40babel/core@7.24.0",
                "pkg:npm/%40babel/parser@7.29.3",
                "pkg:npm/eslint@9.0.0",
                "pkg:npm/left-pad@1.3.0",
            ],
            "aliases must report the real package, not the local label"
        );
        let joined = names(&inv).join(" ");
        assert!(
            !joined.contains("npm-babel-parser"),
            "alias label leaked as a package"
        );
        assert!(
            !joined.contains("eslint-v9"),
            "alias label leaked as a package"
        );
    }

    // Classic yarn v1 spells aliases the same way.
    #[test]
    fn yarn_classic_alias_resolves() {
        let path = tmp(
            "yarn-classic-alias.lock",
            "\"scheduler-0-13@npm:scheduler@0.13.0\":\n  version \"0.13.0\"\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:npm/scheduler@0.13.0"]);
    }

    #[test]
    fn yarn_workspace_entries_are_excluded_not_reported() {
        let path = tmp(
            "yarn-workspace.lock",
            "\"my-app@workspace:.\":\n  version: 0.0.0\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n",
        );
        let inv = parse_yarn_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:npm/left-pad@1.3.0"]);
        assert_eq!(inv.notes.len(), 1);
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let path = tmp("broken.json", "{not json");
        assert!(matches!(
            parse_package_lock(&path),
            Err(ParseError::Unrecognized { .. })
        ));
    }

    #[test]
    fn scope_splitting() {
        assert_eq!(
            split_scope("@angular/core"),
            (Some("@angular".into()), "core".into())
        );
        assert_eq!(split_scope("left-pad"), (None, "left-pad".into()));
        assert_eq!(
            yarn_spec_name("@angular/core@npm:^17.0.0"),
            Some(YarnEntry::Registry("@angular/core".into()))
        );
        assert_eq!(
            yarn_spec_name("left-pad@^1.0.0"),
            Some(YarnEntry::Registry("left-pad".into()))
        );
    }
}
