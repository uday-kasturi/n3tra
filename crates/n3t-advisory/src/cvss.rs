//! CVSS v3.x base score, computed from the vector string.
//!
//! Computed rather than taken from a `database_specific.severity` label, because
//! those labels are inconsistent across advisory sources and `--cvss 7.0` has to
//! mean the same thing everywhere.
//!
//! CVSS v4.0 vectors are recognized but not scored: the v4 algorithm is a lookup
//! over ~270 equivalence classes and getting it subtly wrong would be worse than
//! declining. A v4-only advisory reports its severity label with no numeric
//! score rather than a fabricated one.

use n3t_core::verdict::Severity;

/// A parsed CVSS vector.
#[derive(Debug, Clone, PartialEq)]
pub struct Cvss {
    /// The original vector string.
    pub vector: String,
    /// Base score, if computable (v3.x only).
    pub score: Option<f64>,
    /// Version, e.g. `3.1`.
    pub version: String,
}

impl Cvss {
    /// Parse a CVSS vector and compute its base score where possible.
    pub fn parse(vector: &str) -> Option<Self> {
        let vector = vector.trim();
        let version = vector.strip_prefix("CVSS:")?.split('/').next()?.to_string();

        let score = if version.starts_with('3') {
            score_v3(vector)
        } else {
            None
        };

        Some(Cvss {
            vector: vector.to_string(),
            score,
            version,
        })
    }

    /// Severity band for this score.
    pub fn severity(&self) -> Option<Severity> {
        self.score.map(severity_from_score)
    }
}

/// Map a numeric score onto a band, per the CVSS v3.1 qualitative scale.
pub fn severity_from_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn metric<'a>(vector: &'a str, key: &str) -> Option<&'a str> {
    vector
        .split('/')
        .filter_map(|part| part.split_once(':'))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

fn score_v3(vector: &str) -> Option<f64> {
    let scope_changed = metric(vector, "S")? == "C";

    let av = match metric(vector, "AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match metric(vector, "AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    // Privileges Required is scored differently when scope changes.
    let pr = match (metric(vector, "PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let ui = match metric(vector, "UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };

    let cia = |key: &str| -> Option<f64> {
        match metric(vector, key)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };

    Some(roundup(base))
}

/// CVSS v3.1 "Roundup": round *up* to one decimal place, using the integer
/// formulation from the spec to avoid float representation error.
fn roundup(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) as f64 + 1.0) / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        Cvss::parse(v).and_then(|c| c.score).unwrap_or(-1.0)
    }

    // Reference vectors with scores published in the CVSS v3.1 specification and
    // in the corresponding NVD entries.
    #[test]
    fn known_vectors_score_correctly() {
        // CVE-2019-0708 (BlueKeep)
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        // CVE-2020-1472 (Zerologon) — scope changed
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        // Low-impact local. ISS 0.22 → Impact 1.4124, Exploitability 0.33300,
        // base 1.74540, roundup 1.8.
        assert_eq!(score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), 1.8);
        // Common "high" shape
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 6.5);
        // No impact at all scores zero, not an error.
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
    }

    #[test]
    fn v30_also_scores() {
        assert_eq!(score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
    }

    // Declining to score is correct behavior, not a bug: a fabricated v4 score
    // would silently change what `--cvss 7.0` gates on.
    #[test]
    fn v4_is_recognized_but_not_scored() {
        let c = Cvss::parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
            .expect("v4 vector should parse");
        assert_eq!(c.version, "4.0");
        assert_eq!(c.score, None);
        assert_eq!(c.severity(), None);
    }

    #[test]
    fn severity_bands_match_the_qualitative_scale() {
        assert_eq!(severity_from_score(9.8), Severity::Critical);
        assert_eq!(severity_from_score(9.0), Severity::Critical);
        assert_eq!(severity_from_score(8.9), Severity::High);
        assert_eq!(severity_from_score(7.0), Severity::High);
        assert_eq!(severity_from_score(6.9), Severity::Medium);
        assert_eq!(severity_from_score(4.0), Severity::Medium);
        assert_eq!(severity_from_score(3.9), Severity::Low);
    }

    #[test]
    fn roundup_rounds_up_not_to_nearest() {
        assert_eq!(roundup(4.01), 4.1);
        assert_eq!(roundup(4.0), 4.0);
        assert_eq!(roundup(6.44), 6.5);
    }

    #[test]
    fn malformed_vectors_return_none_not_panic() {
        for v in [
            "",
            "nonsense",
            "CVSS:3.1/",
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N",
        ] {
            let parsed = Cvss::parse(v);
            assert!(
                parsed.is_none() || parsed.is_some_and(|c| c.score.is_none()),
                "{v}"
            );
        }
    }
}
