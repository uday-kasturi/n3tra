//! INV-12: the permitted-binary allowlist.
//!
//! n3tra must produce a complete, correct result on a machine where no other
//! security tooling is installed. The single permitted class of external
//! invocation is the ecosystem's own resolver and build tooling — software the
//! developer already runs to build their project.
//!
//! The distinction that matters: is this infrastructure the developer already
//! runs, or is it a competing product whose job n3tra claims to do? The first is
//! fine. The second is never. So the allowlist is enforced here, at the one place
//! that can spawn a process, rather than trusted to reviewer vigilance.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// Binaries n3tra may invoke.
///
/// Every entry is a package manager, resolver, or build tool the developer
/// already has. Notably absent, and permanently so: `syft`, `trivy`, `grype`,
/// `osv-scanner`, `snyk`, `socket`. Those appear in dev-dependencies and CI as a
/// differential *test harness* only.
pub const PERMITTED: &[&str] = &[
    // Python
    "python",
    "python3",
    "pip",
    "pip3",
    "uv",
    "poetry",
    // JavaScript
    "npm",
    "pnpm",
    "yarn",
    "node",
    // Rust / Go
    "cargo",
    "go",
    // OS packages
    "dpkg-query",
    "dpkg",
    "apk",
    "rpm",
];

/// Why an external invocation failed.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// INV-12 violation. This is a defect in n3tra, not a user environment
    /// problem, so it is loud rather than a silent fallback.
    #[error("INV-12 violation: `{0}` is not on the permitted-binary allowlist")]
    NotPermitted(String),
    /// The tool is not installed. Per INV-5 the caller reports `unknown` for the
    /// affected ecosystem rather than guessing.
    #[error("`{0}` not found on PATH")]
    NotFound(String),
    /// The tool ran and failed.
    #[error("`{cmd}` exited with {code:?}: {stderr}")]
    Failed {
        /// The command that failed.
        cmd: String,
        /// Its exit code.
        code: Option<i32>,
        /// Captured stderr, truncated.
        stderr: String,
    },
    /// Spawning failed for a reason other than the binary being absent.
    #[error("failed to run `{cmd}`: {source}")]
    Spawn {
        /// The command.
        cmd: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// How long any single inventory command may run before we give up and report
/// `unknown`. A resolver that hangs must not hang the scan.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Run a permitted binary, capturing stdout.
///
/// Refuses anything not on [`PERMITTED`].
pub fn run(program: &str, args: &[&str], cwd: &Path) -> Result<String, ExecError> {
    if !PERMITTED.contains(&program) {
        return Err(ExecError::NotPermitted(program.to_string()));
    }
    run_inner(program, args, cwd)
}

/// Shared spawn path. Never call directly: the allowlist check lives in the
/// public wrappers, and this deliberately does not repeat it so there is exactly
/// one place per entry point where the check can be seen to happen.
fn run_inner(program: &str, args: &[&str], cwd: &Path) -> Result<String, ExecError> {
    let output: Output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        // Inventory commands must never prompt, page, or colorize.
        .env("NO_COLOR", "1")
        .env("CI", "1")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ExecError::NotFound(program.to_string())
            } else {
                ExecError::Spawn {
                    cmd: program.to_string(),
                    source: e,
                }
            }
        })?;

    let cmd = format!("{program} {}", args.join(" "));

    // `npm ls` exits non-zero on peer-dependency complaints while still emitting
    // a complete tree, so a usable stdout beats a clean exit code here.
    if !output.status.success() && output.stdout.is_empty() {
        let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        stderr.truncate(500);
        return Err(ExecError::Failed {
            cmd,
            code: output.status.code(),
            stderr,
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run a permitted binary given by path rather than by name.
///
/// Needed for project-local interpreters (`.venv/bin/python`). The allowlist is
/// checked against the file name. Callers must construct these paths themselves —
/// never from repository-controlled input, since a hostile repo could otherwise
/// place an executable named `python` anywhere and have it invoked.
pub fn run_path(program: &Path, args: &[&str], cwd: &Path) -> Result<String, ExecError> {
    let name = program
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .trim_end_matches(".exe");
    if !PERMITTED.contains(&name) {
        return Err(ExecError::NotPermitted(program.display().to_string()));
    }
    run_inner(program.as_os_str().to_string_lossy().as_ref(), args, cwd)
}

/// Whether a permitted binary is present on PATH.
pub fn available(program: &str) -> bool {
    if !PERMITTED.contains(&program) {
        return false;
    }
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    // INV-12, asserted directly: n3tra must never shell out to a competing
    // scanner. If one of these ever becomes permitted, this test fails loudly.
    #[test]
    fn competing_scanners_are_never_permitted() {
        for tool in [
            "syft",
            "trivy",
            "grype",
            "osv-scanner",
            "snyk",
            "socket",
            "cdxgen",
        ] {
            assert!(!PERMITTED.contains(&tool), "{tool} must not be permitted");
            let err = run(tool, &["--version"], Path::new("."));
            assert!(
                matches!(err, Err(ExecError::NotPermitted(_))),
                "{tool} was not refused"
            );
            assert!(!available(tool), "{tool} reported available");
        }
    }

    #[test]
    fn arbitrary_binaries_are_refused() {
        for tool in ["sh", "bash", "curl", "rm", "/bin/sh"] {
            assert!(matches!(
                run(tool, &[], Path::new(".")),
                Err(ExecError::NotPermitted(_))
            ));
        }
    }

    #[test]
    fn permitted_list_is_resolvers_and_build_tools_only() {
        // A permitted entry must be a package manager, resolver, or runtime the
        // developer already runs. Guard against the list growing sideways.
        assert!(PERMITTED.contains(&"npm"));
        assert!(PERMITTED.contains(&"cargo"));
        assert!(PERMITTED.contains(&"dpkg-query"));
        assert!(
            PERMITTED.len() < 30,
            "allowlist is growing suspiciously large"
        );
    }

    #[test]
    fn missing_binary_is_distinguishable_from_failure() {
        // `go` is permitted but may well be absent here; either outcome is fine,
        // what matters is that absence is its own error variant so the caller can
        // report `unknown` rather than treating it as a clean result.
        match run("go", &["version"], Path::new(".")) {
            Ok(_) | Err(ExecError::Failed { .. }) => {}
            Err(ExecError::NotFound(_)) => {}
            Err(e) => panic!("unexpected error shape: {e}"),
        }
    }
}
