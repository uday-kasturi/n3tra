//! Python: `requirements.txt`, `poetry.lock`, `uv.lock`, `pyproject.toml`.
//!
//! Only `==` pins yield a version. A range constraint (`>=1.0`) is recorded
//! without one, because a PURL with no version cannot be matched against an
//! advisory — and reporting such a package as clean would be a lie. The audit
//! path turns those into an explicit gap (INV-5).

use std::path::{Path, PathBuf};

use n3t_core::confidence::Confidence;
use n3t_core::purl::Purl;

use crate::{exec, read, DiscoveredPackage, Ecosystem, Inventory, InventorySource, ParseError};

/// The Python ecosystem.
pub struct Python;

/// Lockfile format versions this parser understands. A file declaring anything
/// else becomes a gap rather than a partial parse.
const SUPPORTED_UV_LOCK_VERSIONS: &[u64] = &[1];

impl Ecosystem for Python {
    fn id(&self) -> &'static str {
        "pypi"
    }

    fn detect(&self, root: &Path) -> bool {
        [
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
        ]
        .iter()
        .any(|f| root.join(f).exists())
    }

    /// Native inventory is the *installed environment*, which is only meaningful
    /// when there is a project-local one. Scanning a project must not silently
    /// inventory the system Python and present it as the project's dependencies.
    fn native(&self, root: &Path) -> Option<Result<Inventory, ParseError>> {
        let venv_python = venv_python(root)?;
        let raw =
            exec::run_path(&venv_python, &["-m", "pip", "list", "--format=json"], root).ok()?;
        Some(Ok(parse_pip_list(&raw, &venv_python.display().to_string())))
    }

    fn fallback(&self, root: &Path) -> Result<Inventory, ParseError> {
        let mut inv = Inventory::default();
        let mut found_pinned_source = false;

        // Lockfiles first: they pin, and pins are what advisory matching needs.
        let uv = root.join("uv.lock");
        if uv.exists() {
            inv.merge(parse_uv_lock(&uv)?);
            found_pinned_source = true;
        }

        let poetry = root.join("poetry.lock");
        if poetry.exists() {
            inv.merge(parse_poetry_lock(&poetry)?);
            found_pinned_source = true;
        }

        let reqs = root.join("requirements.txt");
        if reqs.exists() {
            inv.merge(parse_requirements(&reqs)?);
            found_pinned_source = true;
        }

        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() && !found_pinned_source {
            // Declared ranges only. Recorded so the package is visible, but
            // unversioned, so audit will report it as uncheckable rather than clean.
            inv.merge(parse_pyproject(&pyproject)?);
        }

        Ok(inv)
    }
}

/// A project-local interpreter, if one exists.
fn venv_python(root: &Path) -> Option<PathBuf> {
    for candidate in [
        ".venv/bin/python",
        "venv/bin/python",
        ".venv/Scripts/python.exe",
    ] {
        let path = root.join(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    std::env::var_os("VIRTUAL_ENV")
        .map(|v| PathBuf::from(v).join("bin/python"))
        .filter(|p| p.exists())
}

#[derive(serde::Deserialize)]
struct PipListEntry {
    name: String,
    version: String,
}

fn parse_pip_list(raw: &str, tool: &str) -> Inventory {
    let mut inv = Inventory::default();
    match serde_json::from_str::<Vec<PipListEntry>>(raw) {
        Ok(entries) => {
            for entry in entries {
                if let Ok(purl) = Purl::new("pypi", None, entry.name, Some(entry.version)) {
                    inv.packages.push(DiscoveredPackage {
                        purl,
                        confidence: Confidence::High,
                        direct: false,
                    });
                }
            }
            inv.sources.push(InventorySource::Native {
                tool: format!("{tool} -m pip list"),
            });
        }
        Err(e) => inv.gap("pypi", format!("pip list output not understood: {e}")),
    }
    inv
}

fn parse_uv_lock(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_uv_lock_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_uv_lock_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| ParseError::Unrecognized {
        path: path_label.to_string(),
        detail: format!("invalid TOML: {e}"),
    })?;

    let mut inv = Inventory::default();
    let version = doc
        .get("version")
        .and_then(toml::Value::as_integer)
        .map(|v| v as u64);

    // Fail loudly on a format we do not understand, rather than returning the
    // subset we happened to recognize.
    if let Some(v) = version {
        if !SUPPORTED_UV_LOCK_VERSIONS.contains(&v) {
            inv.gap(
                "pypi",
                format!(
                    "uv.lock version {v} not supported (known: {SUPPORTED_UV_LOCK_VERSIONS:?})"
                ),
            );
            return Ok(inv);
        }
    }

    collect_toml_packages(&doc, &mut inv);
    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: version,
    });
    Ok(inv)
}

fn parse_poetry_lock(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_poetry_lock_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_poetry_lock_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| ParseError::Unrecognized {
        path: path_label.to_string(),
        detail: format!("invalid TOML: {e}"),
    })?;

    let mut inv = Inventory::default();
    collect_toml_packages(&doc, &mut inv);
    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: None,
    });
    Ok(inv)
}

/// Is this entry a local workspace member rather than a registry package?
///
/// `uv.lock` marks these `source = { editable = "." }` or `{ directory = ... }`;
/// `poetry.lock` uses `[package.source] type = "directory"`. Like pnpm's `file:`
/// entries they have no registry identity and therefore no advisory to match,
/// but they must be *excluded on purpose* rather than dropped for want of a
/// version field.
fn is_local_source(entry: &toml::Value) -> bool {
    let Some(source) = entry.get("source") else {
        return false;
    };
    if let Some(table) = source.as_table() {
        if table.contains_key("editable")
            || table.contains_key("directory")
            || table.contains_key("virtual")
        {
            return true;
        }
        if let Some(ty) = table.get("type").and_then(toml::Value::as_str) {
            return matches!(ty, "directory" | "file");
        }
    }
    false
}

/// Both `uv.lock` and `poetry.lock` use `[[package]]` with `name` and `version`.
fn collect_toml_packages(doc: &toml::Value, inv: &mut Inventory) {
    let Some(packages) = doc.get("package").and_then(toml::Value::as_array) else {
        return;
    };

    let mut local = 0usize;
    let mut unversioned: Vec<String> = Vec::new();

    for entry in packages {
        let Some(name) = entry.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let version = entry.get("version").and_then(toml::Value::as_str);

        if is_local_source(entry) {
            local += 1;
            continue;
        }

        // A registry package with no version cannot be matched against an
        // advisory, and dropping it silently would shrink the denominator while
        // the scan still looked complete.
        let Some(version) = version else {
            unversioned.push(name.to_string());
            continue;
        };

        if let Ok(purl) = Purl::new("pypi", None, name, Some(version.to_string())) {
            inv.packages.push(DiscoveredPackage {
                purl,
                confidence: Confidence::High,
                direct: false,
            });
        }
    }

    if local > 0 {
        inv.note(format!(
            "{local} local workspace member(s) excluded (editable/directory sources have \
             no registry identity; their own dependencies are listed separately)"
        ));
    }

    if !unversioned.is_empty() {
        let sample: Vec<&str> = unversioned.iter().take(3).map(String::as_str).collect();
        inv.gap(
            "pypi",
            format!(
                "{} lockfile entr(ies) have no version and no local source (e.g. {}); \
                 these were NOT checked",
                unversioned.len(),
                sample.join(", ")
            ),
        );
    }
}

fn parse_requirements(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_requirements_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_requirements_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let mut inv = Inventory::default();
    let mut unpinned = 0usize;

    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        // `-r other.txt`, `-e .`, `--index-url ...`: not package pins.
        if line.starts_with('-') {
            continue;
        }
        // Direct URLs and VCS refs carry no reliable PyPI identity.
        if line.contains("://") {
            unpinned += 1;
            continue;
        }

        // Drop environment markers, then extras.
        let spec = line.split(';').next().unwrap_or(line).trim();
        let (name_part, version) = match spec.split_once("==") {
            Some((n, v)) => (n, Some(v.trim().trim_end_matches(".*").to_string())),
            None => (spec, None),
        };
        let name = name_part
            .split(['[', '>', '<', '~', '!', '=', ' '])
            .next()
            .unwrap_or(name_part)
            .trim();
        if name.is_empty() {
            continue;
        }
        if version.is_none() {
            unpinned += 1;
        }
        if let Ok(purl) = Purl::new("pypi", None, name, version) {
            inv.packages.push(DiscoveredPackage {
                purl,
                confidence: Confidence::High,
                direct: true,
            });
        }
    }

    if unpinned > 0 {
        inv.gap(
            "pypi",
            format!(
                "{unpinned} requirement(s) in {} are unpinned or URL-based; \
                     no version to match advisories against",
                path_label
            ),
        );
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: None,
    });
    Ok(inv)
}

fn parse_pyproject(path: &Path) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_pyproject_str(&text, &path.display().to_string())
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_pyproject_str(text: &str, path_label: &str) -> Result<Inventory, ParseError> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| ParseError::Unrecognized {
        path: path_label.to_string(),
        detail: format!("invalid TOML: {e}"),
    })?;

    let mut inv = Inventory::default();
    let mut count = 0usize;

    if let Some(deps) = doc
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for dep in deps.iter().filter_map(toml::Value::as_str) {
            let name = dep
                .split(['[', '>', '<', '~', '!', '=', ';', ' '])
                .next()
                .unwrap_or(dep)
                .trim();
            if name.is_empty() {
                continue;
            }
            if let Ok(purl) = Purl::new("pypi", None, name, None) {
                inv.packages.push(DiscoveredPackage {
                    purl,
                    confidence: Confidence::Medium,
                    direct: true,
                });
                count += 1;
            }
        }
    }

    if count > 0 {
        inv.gap(
            "pypi",
            format!(
                "{count} dependency range(s) from {} with no lockfile; versions unresolved",
                path_label
            ),
        );
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: None,
    });
    Ok(inv)
}

/// Strip a trailing `#` comment. Not quote-aware, which is correct here:
/// requirements.txt has no quoting construct that can contain a bare `#`.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => line.get(..i).unwrap_or(""),
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n3t-py-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        path
    }

    fn names(inv: &Inventory) -> Vec<String> {
        let mut v: Vec<_> = inv.packages.iter().map(|p| p.purl.to_string()).collect();
        v.sort();
        v
    }

    #[test]
    fn requirements_pins_are_parsed_and_normalized() {
        let path = tmp(
            "requirements.txt",
            "# comment\n\
             Django==4.2.1\n\
             typing_extensions==4.0.0\n\
             requests[security]==2.31.0\n\
             urllib3 == 2.0.7 ; python_version < \"3.9\"\n\
             \n",
        );
        let inv = parse_requirements(&path).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:pypi/django@4.2.1",
                "pkg:pypi/requests@2.31.0",
                "pkg:pypi/typing-extensions@4.0.0",
                "pkg:pypi/urllib3@2.0.7",
            ]
        );
        assert!(inv.gaps.is_empty(), "fully pinned file must produce no gap");
    }

    // INV-5: an unpinned requirement cannot be matched against an advisory, so
    // it must produce a gap rather than being silently dropped from a clean scan.
    #[test]
    fn unpinned_requirements_produce_a_gap() {
        let path = tmp("requirements-unpinned.txt", "flask>=2.0\nrequests\n");
        let inv = parse_requirements(&path).expect("parse");
        assert_eq!(inv.packages.len(), 2);
        assert_eq!(inv.gaps.len(), 1, "unpinned deps must be reported as a gap");
    }

    #[test]
    fn requirements_skips_flags_and_urls() {
        let path = tmp(
            "requirements-flags.txt",
            "-r base.txt\n-e .\n--index-url https://example.com\nhttps://example.com/x.whl\nflask==3.0.0\n",
        );
        let inv = parse_requirements(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:pypi/flask@3.0.0"]);
        assert_eq!(inv.gaps.len(), 1, "the URL requirement is a gap");
    }

    #[test]
    fn poetry_lock_parsed() {
        let path = tmp(
            "poetry.lock",
            "[[package]]\nname = \"Django\"\nversion = \"4.2.1\"\n\n\
             [[package]]\nname = \"idna\"\nversion = \"3.4\"\n",
        );
        let inv = parse_poetry_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:pypi/django@4.2.1", "pkg:pypi/idna@3.4"]);
    }

    #[test]
    fn uv_lock_parsed() {
        let path = tmp(
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        );
        let inv = parse_uv_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:pypi/requests@2.31.0"]);
    }

    // The important failure mode: a format bump must fail loudly, not
    // half-parse. A partial result still looks like a scan.
    #[test]
    fn unknown_uv_lock_version_is_a_gap_not_a_partial_parse() {
        let path = tmp(
            "uv-future.lock",
            "version = 99\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        );
        let inv = parse_uv_lock(&path).expect("parse");
        assert!(
            inv.packages.is_empty(),
            "must not report a partial package list"
        );
        assert_eq!(inv.gaps.len(), 1);
    }

    #[test]
    fn pyproject_ranges_are_unversioned_and_gapped() {
        let path = tmp(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"flask>=2.0\", \"requests\"]\n",
        );
        let inv = parse_pyproject(&path).expect("parse");
        assert_eq!(inv.packages.len(), 2);
        assert!(inv.packages.iter().all(|p| p.purl.version().is_none()));
        assert_eq!(inv.gaps.len(), 1);
    }

    // Regression from the real-world corpus: uv.lock lists the workspace's own
    // packages with `source = { editable = ... }` and no version field. They are
    // not registry packages, so they must be excluded deliberately — not dropped
    // for lacking a version, which is indistinguishable from a parse failure.
    #[test]
    fn uv_lock_local_workspace_members_are_excluded_not_dropped() {
        let path = tmp(
            "uv-workspace.lock",
            "version = 1\n\n             [[package]]\nname = \"myproject\"\nsource = { editable = \".\" }\n\n             [[package]]\nname = \"mycore\"\nsource = { editable = \"core\" }\n\n             [[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n             source = { registry = \"https://pypi.org/simple\" }\n",
        );
        let inv = parse_uv_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:pypi/requests@2.31.0"]);
        assert_eq!(
            inv.notes.len(),
            1,
            "local members must be reported as excluded"
        );
        assert!(
            inv.gaps.is_empty(),
            "a local member is understood, so it is not a gap"
        );
    }

    // The other side of the same coin: an entry with no version and no local
    // source is genuinely not understood, and must become a gap.
    #[test]
    fn unversioned_registry_entry_is_a_gap() {
        let path = tmp(
            "uv-unversioned.lock",
            "version = 1\n\n[[package]]\nname = \"mystery\"\n",
        );
        let inv = parse_uv_lock(&path).expect("parse");
        assert!(inv.packages.is_empty());
        assert_eq!(
            inv.gaps.len(),
            1,
            "unversioned registry entry must be a gap"
        );
    }

    #[test]
    fn poetry_directory_source_is_excluded() {
        let path = tmp(
            "poetry-dir.lock",
            "[[package]]\nname = \"local-lib\"\nversion = \"0.1.0\"\n             [package.source]\ntype = \"directory\"\nurl = \"../local-lib\"\n\n             [[package]]\nname = \"idna\"\nversion = \"3.4\"\n",
        );
        let inv = parse_poetry_lock(&path).expect("parse");
        assert_eq!(names(&inv), ["pkg:pypi/idna@3.4"]);
        assert_eq!(inv.notes.len(), 1);
    }

    #[test]
    fn malformed_toml_is_an_error_not_a_panic() {
        let path = tmp("broken.lock", "this is not [[ toml");
        assert!(matches!(
            parse_poetry_lock(&path),
            Err(ParseError::Unrecognized { .. })
        ));
    }
}
