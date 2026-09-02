//! INV-5: fail open on the build, fail closed on the verdict.
//!
//! The central design decision in this module: **`Clean` is not constructible.**
//! It is *derived*, and only from a verdict whose observation coverage is
//! `Complete`. An attacker who crashes the collector, saturates the ring buffer,
//! bypasses a shim, or moves the build to a kernel n3tra cannot see gets
//! `Unknown` — there is no code path that turns absent evidence into a pass.
//!
//! This is enforced by construction rather than by convention, because the
//! failure it prevents is silent and indistinguishable from success.

use serde::{Deserialize, Serialize};

use crate::confidence::{Confidence, DEFAULT_GATE_FLOOR};

/// Why observation coverage is incomplete.
///
/// Every variant carries enough detail to name the specific cause in output.
/// "Unknown" with no reason is useless to an operator and gets ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnknownReason {
    /// The collector died or was killed mid-build.
    ObserverTerminated {
        /// How far into the build the observer was lost.
        at_build_step: Option<String>,
    },
    /// eBPF probes could not be attached (old kernel, missing capability,
    /// unsupported arch, no BTF). Degrades to L1+L3, not to `Clean`.
    ProbeLoadFailed {
        /// Human-readable cause, surfaced verbatim in the report.
        detail: String,
    },
    /// The ring buffer saturated or the event budget was exhausted. Silent
    /// truncation is forbidden, so this downgrades the whole verdict.
    EventLossPossible {
        /// Events known to have been dropped, if the kernel reported a count.
        dropped: Option<u64>,
    },
    /// INV-11: the build did not execute on the observed kernel, so the event
    /// stream is empty for reasons unrelated to the build being clean.
    BuildRanElsewhere {
        /// Which escape route the build took.
        builder: DetachedBuilder,
    },
    /// A package manager was invoked in a way that evaded the L1 shims
    /// (absolute path, `env -i`, PATH reset).
    ShimBypassed {
        /// The invocation that got around interposition.
        invocation: String,
    },
    /// An ecosystem's native inventory tool was absent and the fallback parser
    /// did not recognize the lockfile format version.
    InventoryUnavailable {
        /// The ecosystem that could not be inventoried.
        ecosystem: String,
        /// Why.
        detail: String,
    },
}

/// INV-11: the specific ways a build escapes the observed kernel.
///
/// These are enumerated rather than collapsed into one variant because each has
/// a different remedy, and an operator seeing "unknown" needs to know which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachedBuilder {
    /// `DOCKER_HOST` points at a daemon on another machine.
    RemoteDockerHost,
    /// `docker buildx` using a remote, cloud, or kubernetes driver.
    BuildxRemoteDriver,
    /// Kata Containers or Firecracker: the build has its own guest kernel.
    MicroVmGuestKernel,
    /// gVisor: the host kernel sees only the sentry's syscalls.
    GvisorSandbox,
    /// The target cgroup never appeared in the observed event stream, cause
    /// undetermined. The catch-all, and deliberately still an `Unknown`.
    TargetCgroupNeverObserved,
}

/// How complete the observation was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "coverage", rename_all = "snake_case")]
pub enum Coverage {
    /// Every configured layer reported successfully for the whole build.
    Complete,
    /// One or more layers were unavailable or lost data.
    Partial {
        /// Non-empty by construction — see [`Coverage::partial`].
        reasons: Vec<UnknownReason>,
    },
}

impl Coverage {
    /// Build a `Partial` coverage. Returns `Complete` only if handed an empty
    /// reason list, so a caller cannot manufacture an unexplained `Partial`.
    pub fn partial(reasons: Vec<UnknownReason>) -> Self {
        if reasons.is_empty() {
            Self::Complete
        } else {
            Self::Partial { reasons }
        }
    }

    /// Merge coverage from multiple layers. Partial is absorbing: any layer
    /// losing data downgrades the whole verdict.
    pub fn merge(self, other: Coverage) -> Self {
        match (self, other) {
            (Coverage::Complete, Coverage::Complete) => Coverage::Complete,
            (Coverage::Partial { mut reasons }, Coverage::Complete)
            | (Coverage::Complete, Coverage::Partial { mut reasons }) => {
                reasons.sort_by_key(|r| format!("{r:?}"));
                Coverage::Partial { reasons }
            }
            (Coverage::Partial { mut reasons }, Coverage::Partial { reasons: other }) => {
                reasons.extend(other);
                reasons.sort_by_key(|r| format!("{r:?}"));
                reasons.dedup();
                Coverage::Partial { reasons }
            }
        }
    }

    /// Reasons coverage is incomplete; empty when `Complete`.
    pub fn reasons(&self) -> &[UnknownReason] {
        match self {
            Coverage::Complete => &[],
            Coverage::Partial { reasons } => reasons,
        }
    }
}

/// Severity class. `Malicious` is deliberately not a CVSS band: `MAL-` advisories
/// say "this package is hostile", not "this package has a flaw", and the two must
/// never be summed into one count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// CVSS 0.1–3.9.
    Low,
    /// CVSS 4.0–6.9.
    Medium,
    /// CVSS 7.0–8.9.
    High,
    /// CVSS 9.0–10.0.
    Critical,
    /// Behavioral criticals from L1/L2 (postinstall spawning a shell, fetch from
    /// a non-registry host followed by an executable write).
    Behavioral,
    /// An OpenSSF `MAL-` advisory: the package itself is hostile.
    Malicious,
}

impl Severity {
    /// INV / Stage 3: hostile packages and behavioral criticals can never be
    /// baselined. Suppressing "this package is hostile" is not a legitimate
    /// operation, so the capability does not exist.
    pub fn baselineable(self) -> bool {
        !matches!(self, Severity::Malicious | Severity::Behavioral)
    }
}

/// A single finding, reduced to what verdict computation needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Stable identity, so a baseline keeps matching across version bumps.
    pub id: String,
    /// Severity class.
    pub severity: Severity,
    /// Attribution confidence of the underlying graph node (INV-8).
    pub confidence: Confidence,
    /// Whether this finding predates the baseline ref.
    pub pre_existing: bool,
}

/// What an operator actually acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Complete coverage, nothing gating. The only passing state.
    Clean,
    /// Complete coverage, at least one gating finding.
    Failed,
    /// Coverage was incomplete. Never a pass, regardless of findings.
    Unknown,
}

/// The result of a scan.
///
/// Construct with [`Verdict::new`]; read the answer with [`Verdict::outcome`].
/// There is deliberately no way to hand-assemble an `Outcome::Clean`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    coverage: Coverage,
    findings: Vec<FindingSummary>,
    gate_floor: Confidence,
    baseline_active: bool,
}

impl Verdict {
    /// Assemble a verdict from observation coverage and findings.
    pub fn new(coverage: Coverage, findings: Vec<FindingSummary>) -> Self {
        Self {
            coverage,
            findings,
            gate_floor: DEFAULT_GATE_FLOOR,
            baseline_active: false,
        }
    }

    /// Raise the confidence floor required for a finding to gate (INV-8).
    pub fn with_gate_floor(mut self, floor: Confidence) -> Self {
        self.gate_floor = floor;
        self
    }

    /// Suppress pre-existing findings, failing only on what is new since the
    /// base ref. Findings that cannot be baselined are unaffected.
    pub fn with_baseline(mut self) -> Self {
        self.baseline_active = true;
        self
    }

    /// The findings that actually gate, after confidence and baseline filtering.
    pub fn gating_findings(&self) -> impl Iterator<Item = &FindingSummary> {
        let floor = self.gate_floor;
        let baseline = self.baseline_active;
        self.findings.iter().filter(move |f| {
            if !f.severity.baselineable() {
                // Malicious and behavioral gate unconditionally: neither the
                // baseline nor the confidence floor can suppress them.
                return true;
            }
            if baseline && f.pre_existing {
                return false;
            }
            f.confidence.gate_eligible(floor)
        })
    }

    /// The verdict.
    ///
    /// INV-5: `Unknown` is checked *before* findings are considered, so partial
    /// coverage can never present as a pass.
    pub fn outcome(&self) -> Outcome {
        if matches!(self.coverage, Coverage::Partial { .. }) {
            return Outcome::Unknown;
        }
        if self.gating_findings().next().is_some() {
            return Outcome::Failed;
        }
        Outcome::Clean
    }

    /// Process exit code. `Unknown` is distinct from both pass and fail so CI
    /// can be configured to treat it as either, deliberately.
    pub fn exit_code(&self) -> i32 {
        match self.outcome() {
            Outcome::Clean => 0,
            Outcome::Failed => 1,
            Outcome::Unknown => 2,
        }
    }

    /// Observation coverage.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// All findings, gating or not.
    pub fn findings(&self) -> &[FindingSummary] {
        &self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        id: &str,
        severity: Severity,
        confidence: Confidence,
        pre_existing: bool,
    ) -> FindingSummary {
        FindingSummary {
            id: id.into(),
            severity,
            confidence,
            pre_existing,
        }
    }

    fn crashed() -> Coverage {
        Coverage::partial(vec![UnknownReason::ObserverTerminated {
            at_build_step: None,
        }])
    }

    #[test]
    fn complete_coverage_no_findings_is_clean() {
        assert_eq!(
            Verdict::new(Coverage::Complete, vec![]).outcome(),
            Outcome::Clean
        );
    }

    // INV-5, the core assertion of this module. An attacker who kills the
    // collector must not thereby obtain a passing scan.
    #[test]
    fn partial_coverage_is_never_clean() {
        let v = Verdict::new(crashed(), vec![]);
        assert_eq!(v.outcome(), Outcome::Unknown);
        assert_ne!(v.outcome(), Outcome::Clean);
        assert_eq!(v.exit_code(), 2);
    }

    // INV-11: an empty event stream because the build ran on another kernel is
    // the most dangerous case, because it is silent. It must be Unknown.
    #[test]
    fn detached_builder_is_unknown_not_clean() {
        for reason in [
            DetachedBuilder::RemoteDockerHost,
            DetachedBuilder::BuildxRemoteDriver,
            DetachedBuilder::MicroVmGuestKernel,
            DetachedBuilder::GvisorSandbox,
            DetachedBuilder::TargetCgroupNeverObserved,
        ] {
            let coverage =
                Coverage::partial(vec![UnknownReason::BuildRanElsewhere { builder: reason }]);
            let v = Verdict::new(coverage, vec![]);
            assert_eq!(
                v.outcome(),
                Outcome::Unknown,
                "{reason:?} presented as clean"
            );
            assert!(
                !v.coverage().reasons().is_empty(),
                "{reason:?} gave no reason"
            );
        }
    }

    // Unknown outranks Failed: partial coverage means we do not know that the
    // findings we have are the whole story.
    #[test]
    fn partial_coverage_outranks_findings() {
        let v = Verdict::new(
            crashed(),
            vec![finding("a", Severity::Critical, Confidence::High, false)],
        );
        assert_eq!(v.outcome(), Outcome::Unknown);
    }

    #[test]
    fn high_confidence_finding_fails() {
        let v = Verdict::new(
            Coverage::Complete,
            vec![finding("a", Severity::High, Confidence::High, false)],
        );
        assert_eq!(v.outcome(), Outcome::Failed);
        assert_eq!(v.exit_code(), 1);
    }

    // INV-8: medium reports but does not gate under the default floor.
    #[test]
    fn medium_confidence_does_not_gate_by_default() {
        let v = Verdict::new(
            Coverage::Complete,
            vec![finding("a", Severity::High, Confidence::Medium, false)],
        );
        assert_eq!(v.outcome(), Outcome::Clean);
        assert_eq!(v.findings().len(), 1, "finding must still be reported");
    }

    #[test]
    fn low_confidence_never_gates_even_at_lowest_floor() {
        let v = Verdict::new(
            Coverage::Complete,
            vec![finding("a", Severity::Critical, Confidence::Low, false)],
        )
        .with_gate_floor(Confidence::Low);
        assert_eq!(v.outcome(), Outcome::Clean);
    }

    #[test]
    fn baseline_suppresses_pre_existing_cve() {
        let v = Verdict::new(
            Coverage::Complete,
            vec![finding("a", Severity::Critical, Confidence::High, true)],
        )
        .with_baseline();
        assert_eq!(v.outcome(), Outcome::Clean);
    }

    // Stage 3 baseline governance: hostile packages and behavioral criticals
    // cannot be baselined away, at any confidence, ever.
    #[test]
    fn malicious_and_behavioral_cannot_be_baselined() {
        for severity in [Severity::Malicious, Severity::Behavioral] {
            assert!(!severity.baselineable(), "{severity:?} was baselineable");
            let v = Verdict::new(
                Coverage::Complete,
                vec![finding("a", severity, Confidence::Low, true)],
            )
            .with_baseline()
            .with_gate_floor(Confidence::High);
            assert_eq!(v.outcome(), Outcome::Failed, "{severity:?} was suppressed");
        }
    }

    #[test]
    fn partial_with_no_reasons_collapses_to_complete() {
        assert_eq!(Coverage::partial(vec![]), Coverage::Complete);
    }

    #[test]
    fn coverage_merge_is_absorbing() {
        let c = Coverage::Complete;
        let p = crashed();
        assert_eq!(c.clone().merge(c.clone()), Coverage::Complete);
        assert!(matches!(
            c.clone().merge(p.clone()),
            Coverage::Partial { .. }
        ));
        assert!(matches!(p.clone().merge(c), Coverage::Partial { .. }));
        assert!(matches!(p.clone().merge(p), Coverage::Partial { .. }));
    }

    #[test]
    fn merged_reasons_are_deduped_and_deterministic() {
        let a = Coverage::partial(vec![
            UnknownReason::BuildRanElsewhere {
                builder: DetachedBuilder::GvisorSandbox,
            },
            UnknownReason::EventLossPossible { dropped: Some(7) },
        ]);
        let b = Coverage::partial(vec![UnknownReason::BuildRanElsewhere {
            builder: DetachedBuilder::GvisorSandbox,
        }]);
        let merged = a.clone().merge(b.clone());
        assert_eq!(merged.reasons().len(), 2);
        assert_eq!(merged, a.merge(b), "merge must be deterministic");
    }
}
