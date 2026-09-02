//! Real-world lockfile corpus.
//!
//! Hand-written fixtures test the shapes you thought of. This corpus tests the
//! shapes that actually exist — and it earned its keep immediately, finding two
//! bugs the fixtures missed:
//!
//! 1. A blank line after `packages:` closed the pnpm section, yielding **zero**
//!    packages from a 500KB lockfile.
//! 2. 109 of vite's 1403 entries (`file:` local paths) were dropped silently,
//!    with no way for a reader to know.
//!
//! Corpus files are pinned by commit SHA in `tests/corpus/CORPUS.lock` and
//! fetched by `scripts/fetch-corpus.sh`. Tests skip cleanly when the corpus is
//! absent, so a fresh clone still runs green without network access.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use n3t_parse::Inventory;

/// Expected package counts, verified by hand against independently computed
/// ground truth (`grep -c '^\[\[package\]\]'` for TOML locks, distinct
/// `name@version` keys for pnpm/yarn/npm).
///
/// `exclusions` counts entries understood but deliberately not reported.
/// A change to any number here is either a regression or a deliberate decision,
/// and either way it must be reviewed rather than absorbed.
struct Expectation {
    name: &'static str,
    packages: usize,
    exclusions: usize,
    gaps: usize,
}

const EXPECTED: &[Expectation] = &[
    Expectation {
        name: "npm-cli",
        packages: 993,
        exclusions: 0,
        gaps: 0,
    },
    Expectation {
        name: "axios",
        packages: 666,
        exclusions: 0,
        gaps: 0,
    },
    // 2383 raw headers. 15 aliases (`eslint-v9@npm:eslint@^9.0.0` and friends)
    // now resolve to their real package, and 9 of those collapse into entries
    // already present — net 2377. One `workspace:` entry is excluded.
    Expectation {
        name: "react",
        packages: 2377,
        exclusions: 1,
        gaps: 0,
    },
    // Monorepo: 176 of babel's 1871 headers are its own `workspace:` members,
    // which are directories rather than registry packages.
    Expectation {
        name: "babel",
        packages: 1573,
        exclusions: 1,
        gaps: 0,
    },
    // 1294 registry + 109 local `file:` paths = 1403 raw keys. The arithmetic
    // reconciling to the raw key count is the point of tracking exclusions.
    Expectation {
        name: "vite",
        packages: 1294,
        exclusions: 1,
        gaps: 0,
    },
    Expectation {
        name: "vue-core",
        packages: 620,
        exclusions: 0,
        gaps: 0,
    },
    Expectation {
        name: "poetry",
        packages: 80,
        exclusions: 0,
        gaps: 0,
    },
    // 174 registry + 2 local workspace members (pydantic, pydantic-core,
    // both `source = { editable = ... }`) = 176 `[[package]]` blocks.
    Expectation {
        name: "pydantic",
        packages: 174,
        exclusions: 1,
        gaps: 0,
    },
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("tests/corpus"))
}

fn scan(dir: &Path) -> Inventory {
    // `false` = lockfile parsers only. Native tooling would need the project's
    // node_modules installed, and the point here is to exercise the parsers.
    n3t_parse::scan(dir, false)
}

fn skip_if_absent(dir: &Path) -> bool {
    if !dir.exists() {
        eprintln!(
            "skipping: {} not present — run ./scripts/fetch-corpus.sh",
            dir.display()
        );
        return true;
    }
    false
}

#[test]
fn corpus_package_counts_are_stable() {
    let root = corpus_root();
    if skip_if_absent(&root) {
        return;
    }

    let mut checked = 0;
    for exp in EXPECTED {
        let dir = root.join(exp.name);
        if !dir.exists() {
            eprintln!("skipping {}: not fetched", exp.name);
            continue;
        }
        let inv = scan(&dir);
        assert_eq!(
            inv.packages.len(),
            exp.packages,
            "{}: package count changed ({} -> {}). Regression, or a deliberate \
             parser change that needs this expectation updated?",
            exp.name,
            exp.packages,
            inv.packages.len()
        );
        assert_eq!(
            inv.notes.len(),
            exp.exclusions,
            "{}: exclusion count changed",
            exp.name
        );
        assert_eq!(
            inv.gaps.len(),
            exp.gaps,
            "{}: coverage gaps changed: {:?}",
            exp.name,
            inv.gaps
        );
        checked += 1;
    }

    assert!(checked > 0, "corpus present but nothing matched EXPECTED");
}

/// The regression that motivated the corpus: a large lockfile must never parse
/// to zero packages while reporting success.
#[test]
fn no_corpus_lockfile_parses_to_nothing() {
    let root = corpus_root();
    if skip_if_absent(&root) {
        return;
    }

    for entry in std::fs::read_dir(&root).expect("read corpus dir").flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let inv = scan(&dir);
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Either real packages, or an explicit gap saying why not. Never both
        // empty — that combination is the silent failure mode.
        assert!(
            !inv.packages.is_empty() || !inv.gaps.is_empty(),
            "{name}: parsed to zero packages with no gap reported"
        );
    }
}

/// Every package must carry a version, or advisory matching silently checks
/// nothing for it.
#[test]
fn corpus_packages_are_fully_versioned() {
    let root = corpus_root();
    if skip_if_absent(&root) {
        return;
    }

    for entry in std::fs::read_dir(&root).expect("read corpus dir").flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // requirements.txt legitimately contains unpinned entries; lockfiles do not.
        if dir.join("requirements.txt").exists() {
            continue;
        }
        let inv = scan(&dir);
        let unversioned: Vec<String> = inv
            .packages
            .iter()
            .filter(|p| p.purl.version().is_none())
            .map(|p| p.purl.to_string())
            .take(5)
            .collect();
        assert!(
            unversioned.is_empty(),
            "{name}: lockfile yielded unversioned packages: {unversioned:?}"
        );
    }
}

/// Scanning a 2000+ package lockfile must not be slow enough that anyone
/// disables the tool. Stage 0 budget is 10s; the real numbers are milliseconds,
/// so this asserts a generous ceiling rather than a tight one.
#[test]
fn corpus_scan_is_fast() {
    let root = corpus_root();
    let react = root.join("react");
    if skip_if_absent(&react) {
        return;
    }

    let start = std::time::Instant::now();
    let inv = scan(&react);
    let elapsed = start.elapsed();

    assert!(
        inv.packages.len() > 2000,
        "expected react's yarn.lock to be large"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "scanning {} packages took {elapsed:?}, over the 10s Stage 0 budget",
        inv.packages.len()
    );
}
