//! INV-8: attribution confidence, with defined consequences.
//!
//! A confidence field with no policy attached is decoration. Each band here
//! carries the *consequences* as methods, so downstream code cannot quietly
//! treat a heuristic attribution as if it were an exact ownership record.

use serde::{Deserialize, Serialize};

/// How certain the file-to-package attribution is.
///
/// Ordering is meaningful: `Low < Medium < High`. Policy may raise the required
/// band, never lower it below the configured floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristic or ambiguous. Never gates, never generates a fixplan.
    Low,
    /// Inferred by path shape or content hash. Reported; does not gate by default.
    Medium,
    /// Exact ownership record: a `RECORD` entry, a dpkg file list, a lockfile entry.
    High,
}

impl Confidence {
    /// May a finding at this band fail a pipeline?
    ///
    /// INV-8: a low-confidence finding must never be the sole justification for
    /// an automated action.
    /// The floor is clamped up to `Medium` first: an operator may raise the bar,
    /// but configuring a `Low` floor must not make heuristic attributions gate.
    pub fn gate_eligible(self, floor: Confidence) -> bool {
        self >= floor.max(Confidence::Medium)
    }

    /// May a fixplan be generated from a finding at this band?
    pub fn may_generate_fixplan(self) -> bool {
        self >= Confidence::Medium
    }

    /// Must a generated fixplan be marked `needs-review`?
    pub fn fixplan_needs_review(self) -> bool {
        self == Confidence::Medium
    }

    /// Should this finding be segregated into the "needs triage" section rather
    /// than presented alongside high-confidence findings?
    pub fn needs_triage_section(self) -> bool {
        self == Confidence::Low
    }
}

/// The default gating floor: high-confidence attributions only.
pub const DEFAULT_GATE_FLOOR: Confidence = Confidence::High;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_low_to_high() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    // INV-8: low never gates and never produces a fixplan, under any floor.
    #[test]
    fn low_confidence_never_acts() {
        for floor in [Confidence::Low, Confidence::Medium, Confidence::High] {
            assert!(
                !Confidence::Low.gate_eligible(floor),
                "low gated at floor {floor:?}"
            );
        }
        assert!(!Confidence::Low.may_generate_fixplan());
        assert!(Confidence::Low.needs_triage_section());
    }

    #[test]
    fn medium_reports_but_does_not_gate_by_default() {
        assert!(!Confidence::Medium.gate_eligible(DEFAULT_GATE_FLOOR));
        assert!(Confidence::Medium.may_generate_fixplan());
        assert!(Confidence::Medium.fixplan_needs_review());
    }

    #[test]
    fn high_gates_and_fixes_cleanly() {
        assert!(Confidence::High.gate_eligible(DEFAULT_GATE_FLOOR));
        assert!(Confidence::High.may_generate_fixplan());
        assert!(!Confidence::High.fixplan_needs_review());
    }

    // Operators may raise the bar, never silently lower it: asking for a Low
    // floor must not make Low findings gate.
    #[test]
    fn floor_cannot_be_lowered_below_medium() {
        assert!(!Confidence::Low.gate_eligible(Confidence::Low));
        assert!(Confidence::Medium.gate_eligible(Confidence::Low));
    }

    #[test]
    fn serde_is_stable_lowercase() {
        let json = serde_json::to_string(&Confidence::High).unwrap_or_default();
        assert_eq!(json, "\"high\"");
    }
}
