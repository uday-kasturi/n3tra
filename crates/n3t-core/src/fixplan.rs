//! The fixplan: a signed, declarative, emit-only remediation proposal.
//!
//! Two invariants are enforced structurally here rather than by convention:
//!
//! - **INV-6**: rungs 3–6 carry a mandatory, finite TTL. The field is not
//!   `Option`, there is no `Permanent` variant, and [`Ttl`] refuses to construct
//!   beyond [`MAX_TTL_DAYS`]. There is no way to express "never expires".
//! - **INV-4**: this crate has no code path that writes to a user repository.
//!   A `FixPlan` is a value. Application is a separate, deliberately boring step
//!   the user invokes.

use serde::{Deserialize, Serialize};

use crate::purl::Purl;

/// The longest a mitigation may defer a finding. Roughly one quarter: long
/// enough to schedule real work, short enough that nobody forgets.
pub const MAX_TTL_DAYS: u32 = 90;

/// Why a TTL was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TtlError {
    /// Zero-day TTLs are meaningless and usually a bug.
    #[error("TTL must be at least 1 day")]
    TooShort,
    /// INV-6: there is no infinite option.
    #[error("TTL must not exceed {MAX_TTL_DAYS} days")]
    TooLong,
}

/// A mandatory, finite expiry on a mitigation.
///
/// Deliberately has no `Default`: a caller must state how long the risk is being
/// accepted for. Without this the tool becomes a machine for accumulating
/// unreviewed monkeypatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ttl {
    expires_at_unix: i64,
    granted_days: u32,
}

impl Ttl {
    /// Grant a mitigation `days` from `now_unix`.
    pub fn days_from(now_unix: i64, days: u32) -> Result<Self, TtlError> {
        if days == 0 {
            return Err(TtlError::TooShort);
        }
        if days > MAX_TTL_DAYS {
            return Err(TtlError::TooLong);
        }
        Ok(Self {
            expires_at_unix: now_unix.saturating_add(i64::from(days).saturating_mul(86_400)),
            granted_days: days,
        })
    }

    /// When this mitigation lapses and the finding reopens.
    pub fn expires_at_unix(self) -> i64 {
        self.expires_at_unix
    }

    /// How many days were granted.
    pub fn granted_days(self) -> u32 {
        self.granted_days
    }

    /// Whether the mitigation has lapsed, reopening its finding.
    pub fn is_expired(self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

/// Where a backported patch came from.
///
/// Rung 3 **transports** patches; it never authors them. The patch is something
/// a human already reviewed — an upstream fix commit or a distro security
/// backport — and this type records exactly which, so the user's own reviewer
/// can diff against the real thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum PatchProvenance {
    /// The upstream fix commit referenced by the advisory.
    UpstreamCommit {
        /// Canonical repository URL.
        repo: String,
        /// Full commit SHA. Never a branch or tag: those move.
        commit: String,
    },
    /// A distribution's reviewed security patch.
    DistroBackport {
        /// `debian`, `rhel`, `alpine`, ...
        distro: String,
        /// The distro's identifier for the patch.
        patch_id: String,
    },
}

/// How cleanly a patch applied.
///
/// Only [`PatchApplication::Clean`] can appear in a fixplan: any conflict, fuzz,
/// or manual hunk selection means n3tra abstains. No judgment is exercised, so
/// none needs reviewing — which is the entire reason rung 3 is shippable by a
/// project with no security-research staff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchApplication {
    /// Applied with zero conflicts and zero fuzz.
    Clean,
}

/// A remediation, by ladder rung.
///
/// Rung 5b (removing a *runtime* dependency proven unused) has no variant,
/// because build-time evidence cannot support it — see [`crate::wording`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rung", rename_all = "snake_case")]
pub enum Rung {
    /// 1 — minimum version bump clearing the advisory, resolved by the
    /// ecosystem's own resolver.
    Upgrade {
        /// Version currently resolved.
        from: String,
        /// Version to move to.
        to: String,
    },
    /// 2 — pin a transitive dependency in the ecosystem's native override format.
    TransitiveOverride {
        /// The direct dependency whose subtree is being overridden.
        via: Purl,
        /// Version to force.
        to: String,
        /// `overrides`, `resolutions`, `[patch]`, `replace`, ...
        mechanism: String,
    },
    /// 3 — transport a patch somebody else already reviewed.
    BackportPatch {
        /// Where the patch came from.
        provenance: PatchProvenance,
        /// Always `Clean`; see [`PatchApplication`].
        application: PatchApplication,
        /// INV-6.
        expires: Ttl,
    },
    /// 4 — guard at the call boundary. Experimental, off by default, per-finding
    /// opt-in, and does not ship unless every shim-escape test is green.
    VirtualPatch {
        /// The symbol being guarded.
        target_symbol: String,
        /// INV-6.
        expires: Ttl,
    },
    /// 5a — strip a build-only artifact that leaked into the runtime image.
    ///
    /// Compilers, headers, codegen tools, test frameworks. The evidence (loaded
    /// during build, absent from the runtime entrypoint's needs) is exactly right
    /// for this case and the risk is near zero.
    StripBuildArtifact {
        /// Path in the final image.
        path: String,
        /// INV-6.
        expires: Ttl,
    },
    /// 6 — sandbox policy restricting egress and writes, plus a time-boxed
    /// documented exception.
    Contain {
        /// Human-readable policy summary.
        policy: String,
        /// INV-6.
        expires: Ttl,
    },
}

impl Rung {
    /// Ladder position, 1–6.
    pub fn number(&self) -> u8 {
        match self {
            Rung::Upgrade { .. } => 1,
            Rung::TransitiveOverride { .. } => 2,
            Rung::BackportPatch { .. } => 3,
            Rung::VirtualPatch { .. } => 4,
            Rung::StripBuildArtifact { .. } => 5,
            Rung::Contain { .. } => 6,
        }
    }

    /// The expiry, for rungs that carry one.
    pub fn ttl(&self) -> Option<Ttl> {
        match self {
            Rung::Upgrade { .. } | Rung::TransitiveOverride { .. } => None,
            Rung::BackportPatch { expires, .. }
            | Rung::VirtualPatch { expires, .. }
            | Rung::StripBuildArtifact { expires, .. }
            | Rung::Contain { expires, .. } => Some(*expires),
        }
    }

    /// Whether this rung requires an explicit opt-in flag (rungs 4–6).
    pub fn requires_opt_in(&self) -> bool {
        self.number() >= 4
    }
}

/// How a proposed fix was checked, cheapest sufficient tier first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyTier {
    /// Lockfile diff proves the vulnerable version left the resolved graph.
    /// Sufficient for most rung 1 and 2 fixes; costs no build.
    ResolverDryRun,
    /// Whole fixplan applied at once and built once; bisect only on failure.
    BatchBuild,
    /// Rebuilt under observation, vulnerable code confirmed absent from the
    /// observed set. Required for rungs 3 and above.
    FullObserved,
}

/// The result of verification.
///
/// `Unverified` is a distinct state, never a quiet downgrade of `Verified`:
/// presenting an unverified fix as verified is the one failure mode that would
/// destroy trust in the remediation plane outright.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verification {
    /// Checked at this tier and passed.
    Verified {
        /// Tier that established the result.
        tier: VerifyTier,
    },
    /// Not checked, with the reason (usually `--verify-budget` exhaustion).
    Unverified {
        /// Why verification did not happen.
        reason: String,
    },
}

impl Verification {
    /// Whether this fix may be presented to a user as verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified { .. })
    }
}

/// One proposed remediation for one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    /// The finding this addresses.
    pub finding_id: String,
    /// The affected package.
    pub package: Purl,
    /// What to do.
    pub rung: Rung,
    /// Whether and how it was checked.
    pub verification: Verification,
    /// INV-8: set when the underlying attribution was `Medium` confidence.
    pub needs_review: bool,
}

/// A complete remediation proposal.
///
/// Emitted, never applied (INV-4). Deterministic: identical inputs must produce
/// a byte-identical plan, or review is impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixPlan {
    /// Schema version, so old plans stay readable.
    pub schema_version: u32,
    /// Commit the plan was computed against.
    pub base_ref: String,
    /// Proposed fixes, sorted for determinism.
    pub fixes: Vec<Fix>,
}

impl FixPlan {
    /// Current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Assemble a plan, sorting fixes into a canonical order.
    pub fn new(base_ref: impl Into<String>, mut fixes: Vec<Fix>) -> Self {
        fixes.sort_by(|a, b| {
            a.finding_id
                .cmp(&b.finding_id)
                .then_with(|| a.package.to_string().cmp(&b.package.to_string()))
                .then_with(|| a.rung.number().cmp(&b.rung.number()))
        });
        Self {
            schema_version: Self::SCHEMA_VERSION,
            base_ref: base_ref.into(),
            fixes,
        }
    }

    /// Fixes whose mitigation has lapsed, reopening their findings.
    pub fn expired(&self, now_unix: i64) -> impl Iterator<Item = &Fix> {
        self.fixes
            .iter()
            .filter(move |f| f.rung.ttl().is_some_and(|t| t.is_expired(now_unix)))
    }

    /// Fixes that must not be presented as verified.
    pub fn unverified(&self) -> impl Iterator<Item = &Fix> {
        self.fixes.iter().filter(|f| !f.verification.is_verified())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;

    fn purl() -> Purl {
        Purl::parse("pkg:npm/left-pad@1.0.0").unwrap_or_else(|_| unreachable!())
    }

    fn ttl(days: u32) -> Ttl {
        Ttl::days_from(NOW, days).unwrap_or_else(|_| unreachable!())
    }

    // INV-6: there is no infinite option, and the type refuses to make one.
    #[test]
    fn ttl_cannot_be_infinite_or_zero() {
        assert_eq!(Ttl::days_from(NOW, 0), Err(TtlError::TooShort));
        assert_eq!(
            Ttl::days_from(NOW, MAX_TTL_DAYS + 1),
            Err(TtlError::TooLong)
        );
        assert!(Ttl::days_from(NOW, MAX_TTL_DAYS).is_ok());
    }

    #[test]
    fn ttl_expires() {
        let t = ttl(30);
        assert!(!t.is_expired(NOW));
        assert!(!t.is_expired(NOW + 29 * 86_400));
        assert!(t.is_expired(NOW + 30 * 86_400));
    }

    // INV-6 at the type level: every rung above 2 carries a TTL, and it is not
    // optional. If a rung is ever added without one, this test fails to compile
    // or fails here.
    #[test]
    fn every_mitigation_rung_carries_a_ttl() {
        let rungs = [
            Rung::BackportPatch {
                provenance: PatchProvenance::UpstreamCommit {
                    repo: "https://github.com/example/lib".into(),
                    commit: "a".repeat(40),
                },
                application: PatchApplication::Clean,
                expires: ttl(30),
            },
            Rung::VirtualPatch {
                target_symbol: "lib.parse".into(),
                expires: ttl(30),
            },
            Rung::StripBuildArtifact {
                path: "/usr/bin/gcc".into(),
                expires: ttl(30),
            },
            Rung::Contain {
                policy: "deny egress".into(),
                expires: ttl(30),
            },
        ];
        for rung in rungs {
            assert!(rung.ttl().is_some(), "rung {} had no TTL", rung.number());
            assert!(rung.number() >= 3);
        }
    }

    #[test]
    fn upgrade_rungs_need_no_ttl_and_no_opt_in() {
        let r = Rung::Upgrade {
            from: "1.0.0".into(),
            to: "1.0.1".into(),
        };
        assert_eq!(r.ttl(), None);
        assert!(!r.requires_opt_in());
        assert!(!Rung::TransitiveOverride {
            via: purl(),
            to: "2.0.0".into(),
            mechanism: "overrides".into()
        }
        .requires_opt_in());
    }

    // Rungs 4-6 are off by default and require explicit opt-in (Stage 4 exit).
    #[test]
    fn risky_rungs_require_opt_in() {
        assert!(Rung::VirtualPatch {
            target_symbol: "x".into(),
            expires: ttl(1)
        }
        .requires_opt_in());
        assert!(Rung::StripBuildArtifact {
            path: "x".into(),
            expires: ttl(1)
        }
        .requires_opt_in());
        assert!(Rung::Contain {
            policy: "x".into(),
            expires: ttl(1)
        }
        .requires_opt_in());
        // Rung 3 transports a reviewed patch, so it is not in the opt-in tier.
        assert!(!Rung::BackportPatch {
            provenance: PatchProvenance::DistroBackport {
                distro: "debian".into(),
                patch_id: "CVE-2026-1234.patch".into()
            },
            application: PatchApplication::Clean,
            expires: ttl(30),
        }
        .requires_opt_in());
    }

    #[test]
    fn unverified_is_never_reported_as_verified() {
        let v = Verification::Unverified {
            reason: "verify budget exhausted".into(),
        };
        assert!(!v.is_verified());
        assert!(Verification::Verified {
            tier: VerifyTier::ResolverDryRun
        }
        .is_verified());
    }

    #[test]
    fn verify_tiers_order_cheapest_first() {
        assert!(VerifyTier::ResolverDryRun < VerifyTier::BatchBuild);
        assert!(VerifyTier::BatchBuild < VerifyTier::FullObserved);
    }

    // Stage 3 exit criterion: identical inputs produce a byte-identical plan.
    #[test]
    fn fixplan_is_deterministic_regardless_of_input_order() {
        let mk = |id: &str| Fix {
            finding_id: id.into(),
            package: purl(),
            rung: Rung::Upgrade {
                from: "1.0.0".into(),
                to: "1.0.1".into(),
            },
            verification: Verification::Verified {
                tier: VerifyTier::ResolverDryRun,
            },
            needs_review: false,
        };
        let a = FixPlan::new("main", vec![mk("b"), mk("a"), mk("c")]);
        let b = FixPlan::new("main", vec![mk("c"), mk("b"), mk("a")]);
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap_or_default(),
            serde_json::to_string(&b).unwrap_or_default()
        );
    }

    #[test]
    fn expired_fixes_are_surfaced() {
        let fix = Fix {
            finding_id: "f1".into(),
            package: purl(),
            rung: Rung::VirtualPatch {
                target_symbol: "x".into(),
                expires: ttl(7),
            },
            verification: Verification::Verified {
                tier: VerifyTier::FullObserved,
            },
            needs_review: false,
        };
        let plan = FixPlan::new("main", vec![fix]);
        assert_eq!(plan.expired(NOW).count(), 0);
        assert_eq!(plan.expired(NOW + 8 * 86_400).count(), 1);
    }
}
