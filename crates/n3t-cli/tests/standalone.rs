//! INV-12: n3tra must work on a machine with no other tooling installed.
//!
//! The strongest form of this check is `scripts/standalone-test.sh`, which builds
//! a static binary into a `scratch` image with `--network none`. But that needs a
//! working Docker daemon, and a check that only runs when the environment
//! cooperates is a check that quietly stops running.
//!
//! So this is the always-on version: invoke the real binary with an **empty
//! environment** and a `PATH` pointing at an empty directory. No `npm`, no `pip`,
//! no `cargo`, no shell — and certainly no `syft`, `trivy`, or `osv-scanner`. If
//! any code path depended on an external binary, inventory breaks here.
//!
//! It does not prove the absence of network calls the way the container test
//! does, which is why both exist.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// An empty directory to point `PATH` at, so lookups find nothing at all.
fn empty_bin_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n3t-empty-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create empty bin dir");
    dir
}

/// Run the CLI with nothing inherited from this process's environment.
fn run_isolated(args: &[&str]) -> (i32, String) {
    let empty = empty_bin_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_n3t"))
        .args(args)
        .current_dir(repo_root())
        .env_clear()
        .env("PATH", &empty)
        // HOME is needed only so the default cache path resolves; every test
        // below passes an explicit --cache-dir anyway.
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("run n3t");

    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn discovered(json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("packages_discovered").and_then(|n| n.as_u64()))
        .unwrap_or_else(|| panic!("no packages_discovered in output:\n{json}"))
}

#[test]
fn inventory_works_with_no_tooling_on_path() {
    // Every lockfile format, with no package manager available to fall back on.
    for (fixture, expected) in [
        ("testbed/npm-vulnerable", 5),
        ("testbed/python-vulnerable", 5),
        ("testbed/clean-project", 1),
    ] {
        let (code, out) = run_isolated(&["scan", fixture, "--format", "json"]);
        assert_eq!(code, 0, "{fixture}: scan failed with no PATH");
        assert_eq!(
            discovered(&out),
            expected,
            "{fixture}: inventory changed when no external tooling was reachable"
        );
    }
}

/// INV-5 in the harshest environment we can build without Docker: no tooling, no
/// cache, offline. The verdict must be `unknown` (exit 2), never `clean`.
#[test]
fn offline_cold_cache_is_unknown_not_clean() {
    let cache = std::env::temp_dir().join(format!("n3t-standalone-cold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);

    for fixture in ["testbed/clean-project", "testbed/npm-vulnerable"] {
        let (code, _) = run_isolated(&[
            "audit",
            fixture,
            "--offline",
            "--cache-dir",
            &cache.display().to_string(),
        ]);
        assert_eq!(
            code, 2,
            "{fixture}: offline with a cold cache must be `unknown` (exit 2), not a pass"
        );
    }
}

/// `scan` performs no advisory lookup, so it must not render anything a reader
/// could take as a security pass — even here, where it genuinely cannot check.
#[test]
fn scan_never_claims_clean_in_isolation() {
    let (_, out) = run_isolated(&["scan", "testbed/npm-vulnerable", "--format", "json"]);
    let doc: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(doc["outcome"], "inventory_only");
    assert_eq!(doc["advisory_check_performed"], false);
}

/// The `--no-native` path must agree with the default path when no native
/// tooling exists, or the two code paths have diverged.
#[test]
fn native_and_fallback_agree_when_no_tooling_exists() {
    for fixture in ["testbed/npm-vulnerable", "testbed/python-vulnerable"] {
        let (_, a) = run_isolated(&["scan", fixture, "--format", "json"]);
        let (_, b) = run_isolated(&["scan", fixture, "--no-native", "--format", "json"]);
        assert_eq!(
            discovered(&a),
            discovered(&b),
            "{fixture}: native and fallback paths disagree with no tooling present"
        );
    }
}
