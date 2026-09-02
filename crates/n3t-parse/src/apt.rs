//! Debian/Ubuntu OS packages.
//!
//! OS packages are usually where the CVE count actually lives in a container
//! build, so this matters more than its size suggests.
//!
//! The distro qualifier is deliberately left off the PURL when it cannot be read
//! from `/etc/os-release`: guessing `debian` for an Ubuntu image would silently
//! match the wrong advisory set.

use std::path::{Path, PathBuf};

use n3t_core::confidence::Confidence;
use n3t_core::purl::Purl;

use crate::{exec, read, DiscoveredPackage, Ecosystem, Inventory, InventorySource, ParseError};

/// Debian-family OS packages.
pub struct Apt;

const DPKG_STATUS: &str = "/var/lib/dpkg/status";

impl Ecosystem for Apt {
    fn id(&self) -> &'static str {
        "deb"
    }

    fn detect(&self, root: &Path) -> bool {
        // Either scanning a live Debian-family system, or a rootfs laid out on
        // disk (an extracted image, a chroot).
        Path::new(DPKG_STATUS).exists() || status_path(root).exists()
    }

    fn native(&self, root: &Path) -> Option<Result<Inventory, ParseError>> {
        // dpkg-query reads the live system database, so it is only meaningful
        // when the scan root is the live system.
        if !Path::new(DPKG_STATUS).exists() || !exec::available("dpkg-query") {
            return None;
        }
        let raw = exec::run(
            "dpkg-query",
            &["-W", "-f=${Package}\\t${Version}\\t${Status}\\n"],
            root,
        )
        .ok()?;
        Some(Ok(parse_dpkg_query(&raw, distro(root))))
    }

    fn fallback(&self, root: &Path) -> Result<Inventory, ParseError> {
        let path = status_path(root);
        let path = if path.exists() {
            path
        } else {
            PathBuf::from(DPKG_STATUS)
        };
        if !path.exists() {
            let mut inv = Inventory::default();
            inv.gap("deb", "no dpkg status database found");
            return Ok(inv);
        }
        parse_dpkg_status(&path, distro(root))
    }
}

fn status_path(root: &Path) -> PathBuf {
    root.join("var/lib/dpkg/status")
}

/// Read the distro ID from `os-release`, so advisories match the right feed.
fn distro(root: &Path) -> Option<String> {
    for candidate in [
        root.join("etc/os-release"),
        PathBuf::from("/etc/os-release"),
    ] {
        let Ok(text) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("ID=") {
                let id = value.trim().trim_matches('"').to_ascii_lowercase();
                if !id.is_empty() {
                    return Some(id);
                }
            }
        }
    }
    None
}

fn push(inv: &mut Inventory, distro: Option<&str>, name: &str, version: &str) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    // Strip the multi-arch suffix: `libc6:amd64` is the package `libc6`.
    let name = name.split(':').next().unwrap_or(name);
    if let Ok(purl) = Purl::new(
        "deb",
        distro.map(str::to_string),
        name,
        Some(version.to_string()),
    ) {
        inv.packages.push(DiscoveredPackage {
            purl,
            confidence: Confidence::High,
            direct: false,
        });
    }
}

fn parse_dpkg_query(raw: &str, distro: Option<String>) -> Inventory {
    let mut inv = Inventory::default();
    for line in raw.lines() {
        let mut fields = line.split('\t');
        let (Some(name), Some(version), status) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // Only fully installed packages are present on disk. A removed-but-
        // config-retained package contributes no files and no vulnerability.
        if !status.is_some_and(|s| s.contains("installed") && !s.starts_with("deinstall")) {
            continue;
        }
        push(&mut inv, distro.as_deref(), name.trim(), version.trim());
    }
    inv.sources.push(InventorySource::Native {
        tool: "dpkg-query -W".into(),
    });
    inv
}

fn parse_dpkg_status(path: &Path, distro: Option<String>) -> Result<Inventory, ParseError> {
    let text = read(path)?;
    parse_dpkg_status_str(&text, &path.display().to_string(), distro)
}

/// Parse from memory rather than from disk.
///
/// The path-based wrapper delegates here. Exposed so the fuzz targets can drive
/// the parser millions of times without touching the filesystem — lockfiles are
/// attacker-influenced input in the threat model (a malicious PR supplies one),
/// so these functions are a real attack surface, not just a convenience.
pub fn parse_dpkg_status_str(
    text: &str,
    path_label: &str,
    distro: Option<String>,
) -> Result<Inventory, ParseError> {
    let mut inv = Inventory::default();

    // RFC822-ish stanzas separated by blank lines.
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut installed = false;

        for line in stanza.lines() {
            // Continuation lines start with whitespace and are never fields.
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            if let Some(v) = line.strip_prefix("Package:") {
                name = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Version:") {
                version = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Status:") {
                let status = v.trim();
                installed = status.ends_with("installed") && !status.starts_with("deinstall");
            }
        }

        if let (Some(name), Some(version), true) = (name, version, installed) {
            push(&mut inv, distro.as_deref(), name, version);
        }
    }

    if inv.packages.is_empty() {
        inv.gap(
            "deb",
            format!("no installed packages parsed from {}", path_label),
        );
    }

    inv.sources.push(InventorySource::Lockfile {
        path: path_label.to_string(),
        format_version: None,
    });
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n3t-apt-{}", std::process::id()));
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

    const STATUS: &str = "\
Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 This is a continuation line, not a field.

Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u3

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0.0

Package: half-installed
Status: install ok unpacked
Version: 2.0.0
";

    #[test]
    fn dpkg_status_parsed_with_distro() {
        let path = tmp("status", STATUS);
        let inv = parse_dpkg_status(&path, Some("debian".into())).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:deb/debian/libc6@2.36-9+deb12u3",
                "pkg:deb/debian/openssl@3.0.11-1~deb12u2"
            ]
        );
    }

    // Only fully installed packages contribute files on disk. Config-files and
    // unpacked states must not be reported as present.
    #[test]
    fn non_installed_states_are_excluded() {
        let path = tmp("status-states", STATUS);
        let inv = parse_dpkg_status(&path, None).expect("parse");
        let joined = names(&inv).join(" ");
        assert!(!joined.contains("removed-thing"));
        assert!(!joined.contains("half-installed"));
    }

    // Guessing the distro would silently match the wrong advisory feed, so an
    // unknown distro yields a namespace-less PURL rather than a default.
    #[test]
    fn unknown_distro_yields_no_namespace() {
        let path = tmp("status-nodistro", STATUS);
        let inv = parse_dpkg_status(&path, None).expect("parse");
        assert_eq!(
            names(&inv),
            [
                "pkg:deb/libc6@2.36-9+deb12u3",
                "pkg:deb/openssl@3.0.11-1~deb12u2"
            ]
        );
    }

    #[test]
    fn multiarch_suffix_stripped() {
        let raw = "libc6:amd64\t2.36-9\tinstall ok installed\n";
        let inv = parse_dpkg_query(raw, Some("debian".into()));
        assert_eq!(names(&inv), ["pkg:deb/debian/libc6@2.36-9"]);
    }

    #[test]
    fn dpkg_query_skips_non_installed() {
        let raw = "openssl\t3.0.11\tinstall ok installed\n\
                   gone\t1.0\tdeinstall ok config-files\n";
        let inv = parse_dpkg_query(raw, None);
        assert_eq!(names(&inv), ["pkg:deb/openssl@3.0.11"]);
    }

    #[test]
    fn empty_status_is_a_gap() {
        let path = tmp("status-empty", "");
        let inv = parse_dpkg_status(&path, None).expect("parse");
        assert!(inv.packages.is_empty());
        assert_eq!(inv.gaps.len(), 1);
    }
}
