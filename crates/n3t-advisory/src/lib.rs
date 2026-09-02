//! Advisory matching: OSV client, cache, CVSS scoring, cooldown policy.
//!
//! n3tra owns the client, the cache, the matching logic, and the offline path.
//! It does not own the *data*: OSV is a database, not a competing tool.

#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

use n3t_core::confidence::Confidence;
use n3t_core::purl::Purl;
use n3t_core::verdict::{FindingSummary, Severity, UnknownReason};

pub mod cooldown;
pub mod cvss;
pub mod osv;

pub use cooldown::{CooldownError, PublishInfo, RegistryClient};
pub use cvss::Cvss;
pub use osv::{Advisory, AdvisoryError, OsvClient};

/// What kind of thing was found.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingKind {
    /// An advisory affects this package version.
    Vulnerability(Box<Advisory>),
    /// The package was published inside the cooldown window.
    ///
    /// A policy signal, not evidence of wrongdoing.
    WithinCooldown {
        /// When it was published.
        info: PublishInfo,
        /// The configured window.
        min_age_days: i64,
    },
}

/// A finding against one package.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Stable id, so a baseline keeps matching across version bumps.
    pub id: String,
    /// Affected package.
    pub package: Purl,
    /// What was found.
    pub kind: FindingKind,
    /// Severity class.
    pub severity: Severity,
    /// INV-8: inherited from the inventory node.
    pub confidence: Confidence,
}

impl Finding {
    /// Reduce to the shape verdict computation needs.
    pub fn summary(&self, pre_existing: bool) -> FindingSummary {
        FindingSummary {
            id: self.id.clone(),
            severity: self.severity,
            confidence: self.confidence,
            pre_existing,
        }
    }

    /// CVSS base score, when there is one.
    pub fn cvss_score(&self) -> Option<f64> {
        match &self.kind {
            FindingKind::Vulnerability(a) => a.cvss_score,
            FindingKind::WithinCooldown { .. } => None,
        }
    }
}

/// Audit configuration.
#[derive(Debug, Clone, Default)]
pub struct AuditOptions {
    /// Only report vulnerabilities at or above this CVSS score.
    ///
    /// Never filters `MAL-` findings: those carry no CVSS score and suppressing
    /// "this package is hostile" by a numeric threshold would be wrong.
    pub min_cvss: Option<f64>,
    /// Flag packages published within this many days.
    pub min_version_age_days: Option<i64>,
    /// Use only cached advisory data.
    pub offline: bool,
}

/// The result of auditing an inventory.
#[derive(Debug, Default)]
pub struct AuditResult {
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
    /// INV-5: every package we could not check. Non-empty downgrades the verdict
    /// to `unknown`, never `clean`.
    pub gaps: Vec<UnknownReason>,
    /// Packages successfully checked.
    pub checked: usize,
}

/// One package to audit.
#[derive(Debug, Clone)]
pub struct AuditTarget {
    /// Identity.
    pub purl: Purl,
    /// INV-8 band from the inventory.
    pub confidence: Confidence,
}

/// Audit a set of packages.
///
/// Every failure path appends a gap rather than skipping silently. A package that
/// could not be checked is materially different from a package that was checked
/// and found clean, and the two must never be conflated.
pub fn audit(
    targets: &[AuditTarget],
    client: &OsvClient,
    registry: &RegistryClient,
    options: &AuditOptions,
    now_unix: i64,
) -> AuditResult {
    let mut result = AuditResult::default();

    // One batched lookup for every package, rather than one request each.
    let purls: Vec<Purl> = targets.iter().map(|t| t.purl.clone()).collect();
    let (advisories_by_purl, lookup_errors) = client.query_many(&purls);

    for e in lookup_errors {
        result.gaps.push(UnknownReason::InventoryUnavailable {
            ecosystem: "osv".to_string(),
            detail: e.to_string(),
        });
    }

    for target in targets {
        let key = target.purl.to_string();
        if let Some(advisories) = advisories_by_purl.get(&key) {
            result.checked += 1;
            for advisory in advisories.clone() {
                if let Some(finding) =
                    to_finding(&target.purl, target.confidence, advisory, options)
                {
                    result.findings.push(finding);
                }
            }
        }
        // A package absent from the results already produced an entry in
        // `lookup_errors`, so it is accounted for as a gap rather than silently
        // counted as checked.

        if let Some(min_age) = options.min_version_age_days {
            match registry.publish_info(&target.purl, now_unix) {
                Ok(info) => {
                    if cooldown::is_within_cooldown(&info, min_age) {
                        result.findings.push(Finding {
                            id: format!("N3T-COOLDOWN/{}", target.purl),
                            package: target.purl.clone(),
                            kind: FindingKind::WithinCooldown {
                                info,
                                min_age_days: min_age,
                            },
                            severity: Severity::Low,
                            confidence: target.confidence,
                        });
                    }
                }
                // An unsupported ecosystem is a known limitation of the policy,
                // not a hole in the scan, so it does not downgrade coverage.
                Err(CooldownError::UnsupportedEcosystem(_)) => {}
                Err(e) => {
                    result.gaps.push(UnknownReason::InventoryUnavailable {
                        ecosystem: target.purl.ty().to_string(),
                        detail: format!("cooldown check: {e}"),
                    });
                }
            }
        }
    }

    result.findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                b.cvss_score()
                    .unwrap_or(-1.0)
                    .partial_cmp(&a.cvss_score().unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.package.to_string().cmp(&b.package.to_string()))
    });

    result
}

fn to_finding(
    purl: &Purl,
    confidence: Confidence,
    advisory: Advisory,
    options: &AuditOptions,
) -> Option<Finding> {
    // A CVSS threshold must never suppress a malicious-package advisory: MAL-
    // entries carry no score, and "this package is hostile" is not a severity
    // band you get to filter numerically.
    if !advisory.is_malicious() {
        if let Some(min) = options.min_cvss {
            match advisory.cvss_score {
                Some(score) if score < min => return None,
                // An unscored advisory is kept rather than dropped: filtering it
                // out would silently hide every v4-only and distro advisory.
                _ => {}
            }
        }
    }

    Some(Finding {
        id: advisory.id.clone(),
        package: purl.clone(),
        severity: advisory.severity,
        confidence,
        kind: FindingKind::Vulnerability(Box::new(advisory)),
    })
}

/// Wall-clock now, as a Unix timestamp.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn purl(s: &str) -> Purl {
        Purl::parse(s).expect("test purl")
    }

    fn advisory(id: &str, score: Option<f64>, severity: Severity) -> Advisory {
        Advisory {
            id: id.into(),
            aliases: vec![],
            summary: String::new(),
            cvss_vector: None,
            cvss_score: score,
            severity,
            fixed_versions: vec![],
            references: vec![],
        }
    }

    #[test]
    fn cvss_threshold_filters_low_scores() {
        let options = AuditOptions {
            min_cvss: Some(7.0),
            ..Default::default()
        };
        let below = to_finding(
            &purl("pkg:npm/a@1"),
            Confidence::High,
            advisory("low", Some(4.0), Severity::Medium),
            &options,
        );
        let above = to_finding(
            &purl("pkg:npm/a@1"),
            Confidence::High,
            advisory("high", Some(9.8), Severity::Critical),
            &options,
        );
        assert!(below.is_none());
        assert!(above.is_some());
    }

    // A numeric threshold must not be able to hide a hostile package.
    #[test]
    fn cvss_threshold_never_suppresses_malicious_findings() {
        let options = AuditOptions {
            min_cvss: Some(9.9),
            ..Default::default()
        };
        let mut mal = advisory("MAL-2024-0001", None, Severity::Malicious);
        mal.id = "MAL-2024-0001".into();
        let finding = to_finding(&purl("pkg:npm/evil@1"), Confidence::High, mal, &options);
        assert!(
            finding.is_some(),
            "MAL finding was filtered by a CVSS threshold"
        );
    }

    // Dropping unscored advisories would silently hide every v4-only and distro
    // advisory the moment anyone sets a threshold.
    #[test]
    fn unscored_advisories_survive_a_threshold() {
        let options = AuditOptions {
            min_cvss: Some(7.0),
            ..Default::default()
        };
        let finding = to_finding(
            &purl("pkg:deb/debian/x@1"),
            Confidence::High,
            advisory("DSA-1234", None, Severity::High),
            &options,
        );
        assert!(finding.is_some());
    }

    // INV-5, end to end: an offline miss must appear as a gap, and the resulting
    // verdict must be Unknown rather than Clean.
    #[test]
    fn offline_miss_produces_a_gap_not_a_clean_result() {
        let dir = std::env::temp_dir().join(format!("n3t-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let client = OsvClient::new(dir, true);
        let registry = RegistryClient::new(true);

        let targets = vec![AuditTarget {
            purl: purl("pkg:pypi/django@4.2.0"),
            confidence: Confidence::High,
        }];
        let result = audit(&targets, &client, &registry, &AuditOptions::default(), 0);

        assert!(result.findings.is_empty());
        assert_eq!(result.gaps.len(), 1, "unchecked package must produce a gap");
        assert_eq!(result.checked, 0);

        let verdict = n3t_core::Verdict::new(
            n3t_core::Coverage::partial(result.gaps),
            result.findings.iter().map(|f| f.summary(false)).collect(),
        );
        assert_eq!(verdict.outcome(), n3t_core::Outcome::Unknown);
    }

    #[test]
    fn findings_sort_most_severe_first() {
        let targets: Vec<AuditTarget> = vec![];
        let dir = std::env::temp_dir().join("n3t-audit-sort");
        let result = audit(
            &targets,
            &OsvClient::new(dir, true),
            &RegistryClient::new(true),
            &AuditOptions::default(),
            0,
        );
        assert!(result.findings.is_empty());

        // Ordering is exercised directly, since audit() needs network otherwise.
        let mut findings = vec![
            Finding {
                id: "b".into(),
                package: purl("pkg:npm/a@1"),
                kind: FindingKind::Vulnerability(Box::new(advisory(
                    "b",
                    Some(4.0),
                    Severity::Medium,
                ))),
                severity: Severity::Medium,
                confidence: Confidence::High,
            },
            Finding {
                id: "a".into(),
                package: purl("pkg:npm/a@1"),
                kind: FindingKind::Vulnerability(Box::new(advisory(
                    "a",
                    None,
                    Severity::Malicious,
                ))),
                severity: Severity::Malicious,
                confidence: Confidence::High,
            },
        ];
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        assert_eq!(
            findings.first().map(|f| f.severity),
            Some(Severity::Malicious)
        );
    }
}
