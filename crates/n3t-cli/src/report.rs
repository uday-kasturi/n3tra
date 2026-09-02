//! Report rendering: human, JSON, SARIF, JUnit.
//!
//! Two rules shape every renderer here:
//!
//! - **INV-8**: low-confidence findings go in their own "needs triage" section.
//!   They must never appear in the same visual register as an exact ownership
//!   record, because a confident wrong answer is worse than no answer.
//! - **INV-9**: usage claims are scoped to one build. `n3t_core::wording::check`
//!   runs over rendered output in tests.
//!
//! Pre-existing findings are always separated from new ones, from the first run,
//! so accepting a baseline is a visible decision rather than an implicit one.

use n3t_advisory::{Finding, FindingKind};
use n3t_core::confidence::Confidence;
use n3t_core::verdict::{Outcome, Severity, UnknownReason, Verdict};
use n3t_parse::{Inventory, InventorySource};

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Terminal-readable.
    Human,
    /// Machine-readable, n3tra's own shape.
    Json,
    /// SARIF 2.1.0, for code-scanning UIs.
    Sarif,
    /// JUnit XML, for CI test panes.
    Junit,
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
        Severity::Behavioral => "BEHAVIORAL",
        Severity::Malicious => "MALICIOUS",
    }
}

fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn describe_gap(reason: &UnknownReason) -> String {
    match reason {
        UnknownReason::ObserverTerminated { at_build_step } => match at_build_step {
            Some(step) => format!("observer terminated during `{step}`"),
            None => "observer terminated mid-build".to_string(),
        },
        UnknownReason::ProbeLoadFailed { detail } => format!("kernel probes unavailable: {detail}"),
        UnknownReason::EventLossPossible { dropped } => match dropped {
            Some(n) => format!("event loss: {n} events dropped"),
            None => "event loss possible".to_string(),
        },
        UnknownReason::BuildRanElsewhere { builder } => {
            format!("build did not run on the observed kernel ({builder:?})")
        }
        UnknownReason::ShimBypassed { invocation } => format!("shim bypassed by `{invocation}`"),
        UnknownReason::InventoryUnavailable { ecosystem, detail } => {
            format!("[{ecosystem}] {detail}")
        }
    }
}

fn finding_line(f: &Finding) -> String {
    match &f.kind {
        FindingKind::Vulnerability(a) => {
            let score = a
                .cvss_score
                .map(|s| format!("{s:.1}"))
                .unwrap_or_else(|| "—".to_string());
            let summary = if a.summary.is_empty() {
                String::new()
            } else {
                format!("  {}", a.summary)
            };
            format!(
                "  {:<10} {:<7} {:<24} {}{}",
                severity_label(f.severity),
                score,
                a.id,
                f.package,
                summary
            )
        }
        FindingKind::WithinCooldown { info, min_age_days } => format!(
            "  {:<10} {:<7} {:<24} {}  published {} days ago (cooldown {} days)",
            "COOLDOWN", "—", "version-cooldown", f.package, info.age_days, min_age_days
        ),
    }
}

/// What the report is reporting on.
///
/// `scan` performs no advisory lookup at all, so it must not render a verdict
/// that reads as a security pass. "Clean" from a run that checked nothing is the
/// same category of lie as "clean" from a crashed collector (INV-5) — it just
/// arrives by a different route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `n3t scan`: inventory only, no advisory lookup.
    Inventory,
    /// `n3t audit`: inventory plus advisory matching.
    Audit,
}

/// Render a human-readable report.
pub fn human(
    inventory: &Inventory,
    findings: &[Finding],
    verdict: &Verdict,
    checked: usize,
    mode: Mode,
) -> String {
    let mut out = String::new();

    out.push_str("n3tra scan report\n");
    out.push_str("=================\n\n");

    // Inventory provenance: a resolver-derived tree and a best-effort file parse
    // are different claims and should not look alike.
    out.push_str(&format!(
        "Packages discovered: {}\n",
        inventory.packages.len()
    ));
    for source in &inventory.sources {
        match source {
            InventorySource::Native { tool } => {
                out.push_str(&format!("  via native tooling: {tool}\n"))
            }
            InventorySource::Lockfile {
                path,
                format_version,
            } => {
                let v = format_version
                    .map(|v| format!(" (format v{v})"))
                    .unwrap_or_default();
                out.push_str(&format!("  via lockfile: {path}{v}\n"));
            }
        }
    }
    // Deliberate exclusions are shown, always. An exclusion nobody can see is
    // still a silent one, which is the whole distinction notes exist to draw.
    for note in &inventory.notes {
        out.push_str(&format!("  excluded: {note}\n"));
    }
    match mode {
        Mode::Audit => out.push_str(&format!(
            "Packages checked against advisories: {checked}\n\n"
        )),
        Mode::Inventory => {
            out.push_str("Advisory check: not performed (`n3t scan` is inventory only)\n\n")
        }
    }

    let (gating, triage): (Vec<_>, Vec<_>) = findings
        .iter()
        .partition(|f| !f.confidence.needs_triage_section());

    if gating.is_empty() {
        out.push_str("No findings at reportable confidence.\n\n");
    } else {
        out.push_str(&format!("Findings ({})\n", gating.len()));
        out.push_str("------------\n");
        for f in &gating {
            out.push_str(&finding_line(f));
            out.push('\n');
        }
        out.push('\n');
    }

    // INV-8: segregated, never mixed in with the above.
    if !triage.is_empty() {
        out.push_str(&format!(
            "Needs triage — low-confidence attribution ({})\n",
            triage.len()
        ));
        out.push_str("These do not gate and do not generate fixes.\n");
        out.push_str("------------\n");
        for f in &triage {
            out.push_str(&finding_line(f));
            out.push('\n');
        }
        out.push('\n');
    }

    // INV-5: gaps are prominent, not a footnote. This section is the difference
    // between "clean" and "we could not tell".
    let gaps = verdict.coverage().reasons();
    if !gaps.is_empty() {
        out.push_str(&format!("Coverage gaps ({})\n", gaps.len()));
        out.push_str("--------------\n");
        for gap in gaps {
            out.push_str(&format!("  {}\n", describe_gap(gap)));
        }
        out.push('\n');
    }

    // Inventory mode has no security verdict to give. Saying "clean" here would
    // let a run that checked nothing read as a pass.
    if mode == Mode::Inventory {
        out.push_str(
            "INVENTORY ONLY — no advisory lookup was performed, so this is not a\n\
             security verdict of any kind. Run `n3t audit` for that.\n",
        );
        return out;
    }

    out.push_str(&match verdict.outcome() {
        Outcome::Clean => "VERDICT: clean — full coverage, nothing gating.\n".to_string(),
        Outcome::Failed => format!(
            "VERDICT: failed — {} gating finding(s).\n",
            verdict.gating_findings().count()
        ),
        Outcome::Unknown => "VERDICT: unknown — coverage was incomplete, so this is NOT a pass.\n\
             Resolve the gaps above before treating this build as checked.\n"
            .to_string(),
    });

    out
}

/// Render n3tra's own JSON shape.
pub fn json(
    inventory: &Inventory,
    findings: &[Finding],
    verdict: &Verdict,
    checked: usize,
    mode: Mode,
) -> String {
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut obj = serde_json::Map::new();
            let mut set = |k: &str, v: serde_json::Value| {
                obj.insert(k.to_string(), v);
            };
            set("id", f.id.clone().into());
            set("package", f.package.to_string().into());
            set("severity", severity_label(f.severity).into());
            set("confidence", confidence_label(f.confidence).into());
            set("gates", f.confidence.gate_eligible(Confidence::High).into());

            match &f.kind {
                FindingKind::Vulnerability(a) => {
                    set("summary", a.summary.clone().into());
                    set("cvss_score", a.cvss_score.into());
                    set("cvss_vector", a.cvss_vector.clone().into());
                    set("fixed_versions", a.fixed_versions.clone().into());
                    set("aliases", a.aliases.clone().into());
                    set("malicious", a.is_malicious().into());
                }
                FindingKind::WithinCooldown { info, min_age_days } => {
                    set("published_at", info.published_at.clone().into());
                    set("age_days", info.age_days.into());
                    set("min_age_days", (*min_age_days).into());
                }
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let outcome = match (mode, verdict.outcome()) {
        // Never emit "clean" from a run that performed no advisory lookup.
        (Mode::Inventory, _) => "inventory_only",
        (Mode::Audit, Outcome::Clean) => "clean",
        (Mode::Audit, Outcome::Failed) => "failed",
        (Mode::Audit, Outcome::Unknown) => "unknown",
    };

    let doc = serde_json::json!({
        "schema_version": 1,
        "mode": match mode { Mode::Inventory => "scan", Mode::Audit => "audit" },
        "outcome": outcome,
        "advisory_check_performed": mode == Mode::Audit,
        "exit_code": verdict.exit_code(),
        "packages_discovered": inventory.packages.len(),
        "packages_checked": checked,
        // Informational, never affects `outcome` — unlike coverage_gaps.
        "exclusions": inventory.notes.clone(),
        "findings": findings_json,
        "coverage_gaps": verdict.coverage().reasons().iter().map(describe_gap).collect::<Vec<_>>(),
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High | Severity::Malicious | Severity::Behavioral => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Render SARIF 2.1.0.
pub fn sarif(findings: &[Finding], verdict: &Verdict) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let text = match &f.kind {
                FindingKind::Vulnerability(a) => format!(
                    "{} affects {} ({}){}",
                    a.id,
                    f.package,
                    severity_label(f.severity),
                    if a.summary.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", a.summary)
                    }
                ),
                FindingKind::WithinCooldown { info, min_age_days } => format!(
                    "{} was published {} days ago, inside the {}-day cooldown window",
                    f.package, info.age_days, min_age_days
                ),
            };
            serde_json::json!({
                "ruleId": f.id,
                "level": sarif_level(f.severity),
                "message": { "text": text },
                "properties": {
                    "attributionConfidence": confidence_label(f.confidence),
                    "gates": f.confidence.gate_eligible(Confidence::High),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": "." }
                    }
                }]
            })
        })
        .collect();

    // Coverage gaps ride along as results too. A SARIF consumer that only reads
    // results would otherwise see an empty, passing-looking report for a scan
    // that never actually checked anything.
    let mut all = results;
    for gap in verdict.coverage().reasons() {
        all.push(serde_json::json!({
            "ruleId": "n3tra/coverage-gap",
            "level": "warning",
            "message": { "text": format!("Coverage gap — this scan is not a pass: {}", describe_gap(gap)) },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "." } } }]
        }));
    }

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "n3tra",
                "informationUri": "https://github.com/lazerwild/n3tra",
                "version": env!("CARGO_PKG_VERSION"),
            }},
            "results": all
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render JUnit XML.
pub fn junit(findings: &[Finding], verdict: &Verdict) -> String {
    let gaps = verdict.coverage().reasons();
    let total = findings.len() + gaps.len();

    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuites name=\"n3tra\" tests=\"{total}\" failures=\"{}\" errors=\"{}\">\n",
        findings.len(),
        gaps.len()
    ));
    out.push_str(&format!(
        "  <testsuite name=\"advisories\" tests=\"{}\" failures=\"{}\">\n",
        findings.len(),
        findings.len()
    ));
    for f in findings {
        let name = xml_escape(&format!("{} {}", f.package, f.id));
        let msg = xml_escape(finding_line(f).trim());
        out.push_str(&format!("    <testcase name=\"{name}\">\n"));
        out.push_str(&format!(
            "      <failure type=\"{}\" message=\"{msg}\"/>\n",
            severity_label(f.severity)
        ));
        out.push_str("    </testcase>\n");
    }
    out.push_str("  </testsuite>\n");

    // Gaps are errors, not failures: the distinction is exactly INV-5's, between
    // "we found a problem" and "we could not tell".
    out.push_str(&format!(
        "  <testsuite name=\"coverage\" tests=\"{}\" errors=\"{}\">\n",
        gaps.len(),
        gaps.len()
    ));
    for gap in gaps {
        let msg = xml_escape(&describe_gap(gap));
        out.push_str("    <testcase name=\"coverage-gap\">\n");
        out.push_str(&format!(
            "      <error type=\"coverage\" message=\"{msg}\"/>\n"
        ));
        out.push_str("    </testcase>\n");
    }
    out.push_str("  </testsuite>\n");
    out.push_str("</testsuites>\n");
    out
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use n3t_advisory::Advisory;
    use n3t_core::purl::Purl;
    use n3t_core::verdict::{Coverage, DetachedBuilder};

    fn purl(s: &str) -> Purl {
        Purl::parse(s).expect("test purl")
    }

    fn vuln_finding(id: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            id: id.into(),
            package: purl("pkg:npm/left-pad@1.3.0"),
            severity,
            confidence,
            kind: FindingKind::Vulnerability(Box::new(Advisory {
                id: id.into(),
                aliases: vec![],
                summary: "Something bad".into(),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
                cvss_score: Some(9.8),
                severity,
                fixed_versions: vec!["1.3.1".into()],
                references: vec![],
            })),
        }
    }

    fn detached_coverage() -> Coverage {
        Coverage::partial(vec![UnknownReason::BuildRanElsewhere {
            builder: DetachedBuilder::RemoteDockerHost,
        }])
    }

    // INV-9, enforced mechanically over rendered output rather than by review.
    #[test]
    fn no_renderer_emits_prohibited_wording() {
        let findings = vec![vuln_finding("GHSA-a", Severity::Critical, Confidence::High)];
        let verdict = Verdict::new(detached_coverage(), vec![]);
        let inv = Inventory::default();

        for (name, text) in [
            ("human", human(&inv, &findings, &verdict, 1, Mode::Audit)),
            ("json", json(&inv, &findings, &verdict, 1, Mode::Audit)),
            ("sarif", sarif(&findings, &verdict)),
            ("junit", junit(&findings, &verdict)),
        ] {
            let violations = n3t_core::wording::check(&text);
            assert!(
                violations.is_empty(),
                "{name} emitted prohibited wording: {violations:?}"
            );
        }
    }

    // INV-5 in the user-visible surface. An operator skimming a report must not
    // be able to read `unknown` as a pass.
    #[test]
    fn unknown_verdict_is_stated_as_not_a_pass() {
        let verdict = Verdict::new(detached_coverage(), vec![]);
        let text = human(&Inventory::default(), &[], &verdict, 0, Mode::Audit);
        assert!(text.contains("VERDICT: unknown"));
        assert!(text.contains("NOT a pass"));
        assert!(!text.contains("VERDICT: clean"));
    }

    #[test]
    fn clean_verdict_only_when_coverage_complete() {
        let verdict = Verdict::new(Coverage::Complete, vec![]);
        let text = human(&Inventory::default(), &[], &verdict, 5, Mode::Audit);
        assert!(text.contains("VERDICT: clean"));
    }

    // INV-8: low-confidence findings must be in their own section.
    #[test]
    fn low_confidence_findings_are_segregated() {
        let findings = vec![
            vuln_finding("GHSA-high", Severity::Critical, Confidence::High),
            vuln_finding("GHSA-low", Severity::Critical, Confidence::Low),
        ];
        let verdict = Verdict::new(Coverage::Complete, vec![]);
        let text = human(&Inventory::default(), &findings, &verdict, 2, Mode::Audit);

        let triage_at = text
            .find("Needs triage")
            .expect("triage section must exist");
        let low_at = text.find("GHSA-low").expect("low finding rendered");
        let high_at = text.find("GHSA-high").expect("high finding rendered");
        assert!(
            high_at < triage_at,
            "high-confidence finding must precede the triage section"
        );
        assert!(
            low_at > triage_at,
            "low-confidence finding must sit inside the triage section"
        );
    }

    // A SARIF consumer that reads only `results` must not see an empty, passing
    // report for a scan that never checked anything.
    #[test]
    fn sarif_surfaces_coverage_gaps_as_results() {
        let verdict = Verdict::new(detached_coverage(), vec![]);
        let text = sarif(&[], &verdict);
        assert!(text.contains("n3tra/coverage-gap"));
        assert!(text.contains("not a pass"));
    }

    #[test]
    fn junit_distinguishes_gaps_from_findings() {
        let findings = vec![vuln_finding("GHSA-a", Severity::High, Confidence::High)];
        let verdict = Verdict::new(detached_coverage(), vec![]);
        let text = junit(&findings, &verdict);
        assert!(text.contains("<failure"), "a finding is a failure");
        assert!(
            text.contains("<error"),
            "a coverage gap is an error, not a failure"
        );
    }

    #[test]
    fn all_machine_formats_are_well_formed() {
        let findings = vec![vuln_finding("GHSA-a", Severity::High, Confidence::High)];
        // The verdict must be built from the same findings being rendered, or the
        // report and its outcome disagree.
        let verdict = Verdict::new(
            Coverage::Complete,
            findings.iter().map(|f| f.summary(false)).collect(),
        );
        let inv = Inventory::default();

        let parsed: serde_json::Value =
            serde_json::from_str(&json(&inv, &findings, &verdict, 1, Mode::Audit))
                .expect("json output valid");
        assert_eq!(parsed["outcome"], "failed");

        let parsed: serde_json::Value =
            serde_json::from_str(&sarif(&findings, &verdict)).expect("sarif output valid");
        assert_eq!(parsed["version"], "2.1.0");
    }

    // `scan` checks no advisories, so it must never render anything a reader
    // could take as a security pass — in either the human or the machine format.
    #[test]
    fn inventory_mode_never_claims_clean() {
        let verdict = Verdict::new(Coverage::Complete, vec![]);
        let inv = Inventory::default();

        let text = human(&inv, &[], &verdict, 0, Mode::Inventory);
        assert!(
            !text.contains("VERDICT: clean"),
            "scan must not render a clean verdict"
        );
        assert!(text.contains("INVENTORY ONLY"));

        let parsed: serde_json::Value =
            serde_json::from_str(&json(&inv, &[], &verdict, 0, Mode::Inventory))
                .expect("valid json");
        assert_eq!(parsed["outcome"], "inventory_only");
        assert_eq!(parsed["advisory_check_performed"], false);
    }

    #[test]
    fn audit_mode_does_report_a_verdict() {
        let verdict = Verdict::new(Coverage::Complete, vec![]);
        let parsed: serde_json::Value =
            serde_json::from_str(&json(&Inventory::default(), &[], &verdict, 3, Mode::Audit))
                .expect("valid json");
        assert_eq!(parsed["outcome"], "clean");
        assert_eq!(parsed["advisory_check_performed"], true);
    }

    // Notes and gaps must stay distinguishable in output: one is a decision, the
    // other is a hole, and only the second may change the verdict.
    #[test]
    fn exclusions_are_shown_but_do_not_change_the_verdict() {
        let mut inv = Inventory::default();
        inv.note("109 local path dependenc(ies) excluded");
        let verdict = Verdict::new(Coverage::Complete, vec![]);

        let text = human(&inv, &[], &verdict, 3, Mode::Audit);
        assert!(
            text.contains("excluded: 109 local path"),
            "exclusion must be visible"
        );
        assert!(
            text.contains("VERDICT: clean"),
            "an exclusion must not downgrade the verdict"
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&json(&inv, &[], &verdict, 3, Mode::Audit)).expect("valid json");
        assert_eq!(parsed["exclusions"].as_array().map(Vec::len), Some(1));
        assert_eq!(parsed["outcome"], "clean");
        assert_eq!(parsed["coverage_gaps"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let mut f = vuln_finding("GHSA-<script>", Severity::High, Confidence::High);
        if let FindingKind::Vulnerability(a) = &mut f.kind {
            a.summary = "a & b < c".into();
        }
        let text = junit(&[f], &Verdict::new(Coverage::Complete, vec![]));
        assert!(!text.contains("<script>"));
        assert!(text.contains("&lt;script&gt;"));
    }
}
