//! L0: what the build *claims* it depends on.
//!
//! Inventory strategy, in order:
//!
//! 1. **Native tooling** (`npm ls --json`, `cargo metadata`, `dpkg-query -W`, …).
//!    Permitted under INV-12 because it is the developer's own build
//!    infrastructure. It collapses the long-term maintenance surface, which is
//!    where multi-ecosystem tools historically rot.
//! 2. **Hand-written lockfile parsers**, for when the tool is absent. Versioned
//!    separately, so a format they no longer understand fails loudly as
//!    `unknown` rather than silently under-reporting.
//!
//! That second clause is the important one. A parser that quietly returns 40
//! packages from a 200-package lockfile it half-understands is worse than one
//! that refuses, because the result still *looks* like a scan.

#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

use std::path::Path;

use n3t_core::confidence::Confidence;
use n3t_core::purl::Purl;
use n3t_core::verdict::UnknownReason;

pub mod apt;
pub mod exec;
pub mod npm;
pub mod python;

/// Where an inventory came from. Surfaced in reports so an operator can tell a
/// resolver-derived tree from a best-effort file parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventorySource {
    /// The ecosystem's own tooling produced this.
    Native {
        /// The command that ran, for the report.
        tool: String,
    },
    /// A lockfile was parsed directly.
    Lockfile {
        /// Path relative to the scan root.
        path: String,
        /// Format version, when the format declares one.
        format_version: Option<u64>,
    },
}

/// A package as declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPackage {
    /// Normalized identity.
    pub purl: Purl,
    /// INV-8. A resolver-reported or lockfile-pinned package is `High`; anything
    /// inferred is lower.
    pub confidence: Confidence,
    /// Whether the manifest names it directly, as opposed to it arriving
    /// transitively.
    pub direct: bool,
}

/// The result of inventorying one ecosystem in one directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inventory {
    /// Packages found.
    pub packages: Vec<DiscoveredPackage>,
    /// Where they came from.
    pub sources: Vec<InventorySource>,
    /// INV-5: anything that makes this inventory incomplete. Non-empty means the
    /// verdict downgrades to `unknown`, never `clean`.
    pub gaps: Vec<UnknownReason>,
    /// Things deliberately excluded, with the reason.
    ///
    /// Distinct from [`Inventory::gaps`], and the distinction is load-bearing:
    /// a gap means *we could not tell*, a note means *we understood it and chose
    /// not to report it*. Notes are informational and never affect the verdict;
    /// gaps always downgrade it to `unknown`.
    ///
    /// Anything neither understood nor excludable must be a gap, never a note —
    /// otherwise silent loss reappears wearing a label.
    pub notes: Vec<String>,
}

impl Inventory {
    /// Merge another inventory in, deduplicating by PURL.
    pub fn merge(&mut self, other: Inventory) {
        for pkg in other.packages {
            if let Some(existing) = self.packages.iter_mut().find(|p| p.purl == pkg.purl) {
                existing.direct |= pkg.direct;
                existing.confidence = existing.confidence.max(pkg.confidence);
            } else {
                self.packages.push(pkg);
            }
        }
        self.sources.extend(other.sources);
        self.gaps.extend(other.gaps);
        self.notes.extend(other.notes);
    }

    /// Record something understood and deliberately excluded (see [`Self::notes`]).
    pub fn note(&mut self, detail: impl Into<String>) {
        self.notes.push(detail.into());
    }

    /// Record that part of this ecosystem could not be inventoried.
    pub fn gap(&mut self, ecosystem: &str, detail: impl Into<String>) {
        self.gaps.push(UnknownReason::InventoryUnavailable {
            ecosystem: ecosystem.to_string(),
            detail: detail.into(),
        });
    }

    /// Sort for deterministic output.
    pub fn sort(&mut self) {
        self.packages
            .sort_by(|a, b| a.purl.to_string().cmp(&b.purl.to_string()));
        self.packages.dedup_by(|a, b| a.purl == b.purl);
    }
}

/// Why parsing failed outright.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// Path involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file was read but its structure was not understood.
    ///
    /// Deliberately distinct from "no packages found": this becomes an
    /// `InventoryUnavailable` gap, not an empty-but-clean result.
    #[error("{path}: unrecognized format: {detail}")]
    Unrecognized {
        /// Path involved.
        path: String,
        /// What was not understood.
        detail: String,
    },
}

/// One supported ecosystem.
///
/// Adding an ecosystem must touch only this crate and `n3t-attribute` — never
/// `n3t-core`. If a new ecosystem needs a core change, the abstraction is wrong.
pub trait Ecosystem: Send + Sync {
    /// Stable identifier, matching the PURL type where one exists.
    fn id(&self) -> &'static str;

    /// Whether this ecosystem appears to be present at `root`.
    fn detect(&self, root: &Path) -> bool;

    /// Inventory via the ecosystem's own tooling.
    ///
    /// `None` means the tool is absent and the caller should fall back. `Some(Err)`
    /// means it ran and failed, which is a gap, not a fallback trigger — a
    /// resolver that errors is telling us something the file parser cannot.
    fn native(&self, root: &Path) -> Option<Result<Inventory, ParseError>>;

    /// Inventory by parsing lockfiles directly.
    fn fallback(&self, root: &Path) -> Result<Inventory, ParseError>;
}

/// Every ecosystem shipped in Stage 0.
pub fn ecosystems() -> Vec<Box<dyn Ecosystem>> {
    vec![
        Box::new(python::Python),
        Box::new(npm::Npm),
        Box::new(apt::Apt),
    ]
}

/// Inventory every detected ecosystem at `root`.
///
/// `prefer_native` maps to `--no-native` on the CLI: useful for reproducing a
/// scan on a machine that lacks the toolchains, and for the differential tests.
pub fn scan(root: &Path, prefer_native: bool) -> Inventory {
    let mut combined = Inventory::default();

    for eco in ecosystems() {
        if !eco.detect(root) {
            continue;
        }

        let result = if prefer_native {
            match eco.native(root) {
                Some(result) => Some(result),
                // Tool absent: fall back to file parsing rather than reporting a
                // gap. The lockfile is still authoritative about what was pinned.
                None => Some(eco.fallback(root)),
            }
        } else {
            Some(eco.fallback(root))
        };

        match result {
            Some(Ok(inv)) => combined.merge(inv),
            Some(Err(e)) => {
                let mut inv = Inventory::default();
                inv.gap(eco.id(), e.to_string());
                combined.merge(inv);
            }
            None => {}
        }
    }

    combined.sort();
    combined
}

/// Read a file, mapping I/O errors into [`ParseError`].
pub(crate) fn read(path: &Path) -> Result<String, ParseError> {
    std::fs::read_to_string(path).map_err(|e| ParseError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(s: &str, direct: bool, confidence: Confidence) -> DiscoveredPackage {
        DiscoveredPackage {
            purl: Purl::parse(s).expect("test purl"),
            confidence,
            direct,
        }
    }

    #[test]
    fn merge_deduplicates_and_keeps_strongest_claim() {
        let mut a = Inventory::default();
        a.packages
            .push(pkg("pkg:npm/a@1", false, Confidence::Medium));
        let mut b = Inventory::default();
        b.packages.push(pkg("pkg:npm/a@1", true, Confidence::High));

        a.merge(b);
        assert_eq!(a.packages.len(), 1);
        assert!(a.packages[0].direct, "direct must win over transitive");
        assert_eq!(a.packages[0].confidence, Confidence::High);
    }

    #[test]
    fn merge_accumulates_gaps() {
        let mut a = Inventory::default();
        a.gap("npm", "lockfileVersion 9 unknown");
        let mut b = Inventory::default();
        b.gap("pypi", "poetry absent");
        a.merge(b);
        assert_eq!(a.gaps.len(), 2);
    }

    #[test]
    fn sort_is_deterministic() {
        let mut inv = Inventory::default();
        for name in ["c", "a", "b"] {
            inv.packages
                .push(pkg(&format!("pkg:npm/{name}@1"), false, Confidence::High));
        }
        inv.sort();
        let names: Vec<_> = inv
            .packages
            .iter()
            .map(|p| p.purl.name().to_string())
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
    }
}
