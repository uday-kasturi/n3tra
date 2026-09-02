//! OSV.dev client, cache, and offline path.
//!
//! n3tra owns the client, the cache, and the matching logic; it does not own the
//! data. OSV is a database, not a competing tool — curating vulnerability data
//! independently is a full company's work and would make n3tra strictly worse.
//!
//! Version range matching is done **server-side** by querying with a concrete
//! version. That is a deliberate correctness choice: matching locally would mean
//! reimplementing SemVer, PEP 440, and dpkg version ordering, and a subtly wrong
//! comparator produces false negatives, which are the worst possible defect in a
//! scanner. The cache is therefore keyed by exact PURL, and an offline cache miss
//! is `unknown` (INV-5), never `clean`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use n3t_core::purl::Purl;
use n3t_core::verdict::Severity;
use serde::{Deserialize, Serialize};

use crate::cvss::Cvss;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";

/// OSV caps a batch request; stay well under it.
const BATCH_SIZE: usize = 500;
const CACHE_SCHEMA: u32 = 1;

/// Why an advisory lookup failed.
#[derive(Debug, thiserror::Error)]
pub enum AdvisoryError {
    /// The lookup was not attempted because the client is offline and the cache
    /// had no entry. Becomes a coverage gap, never a pass.
    #[error("offline and no cached advisories for {0}")]
    OfflineCacheMiss(String),
    /// Network or transport failure.
    #[error("querying OSV for {purl}: {detail}")]
    Transport {
        /// Package being queried.
        purl: String,
        /// What went wrong.
        detail: String,
    },
    /// OSV returned something we could not read.
    #[error("OSV response for {purl} not understood: {detail}")]
    Malformed {
        /// Package being queried.
        purl: String,
        /// What went wrong.
        detail: String,
    },
}

/// One advisory affecting one package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    /// OSV id: `GHSA-…`, `CVE-…`, `MAL-…`, `PYSEC-…`.
    pub id: String,
    /// Aliases, so `GHSA-x` and `CVE-y` can be recognized as one finding.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One-line summary.
    #[serde(default)]
    pub summary: String,
    /// CVSS vector, when the advisory carries one.
    #[serde(default)]
    pub cvss_vector: Option<String>,
    /// Computed base score.
    #[serde(default)]
    pub cvss_score: Option<f64>,
    /// Severity class.
    pub severity: Severity,
    /// Versions the advisory says fix the issue, if any. Drives rung 1.
    #[serde(default)]
    pub fixed_versions: Vec<String>,
    /// Advisory URLs.
    #[serde(default)]
    pub references: Vec<String>,
}

impl Advisory {
    /// Whether this is an OpenSSF malicious-package advisory.
    ///
    /// `MAL-` means "this package is hostile", not "this package has a flaw".
    /// The two must never be summed into one count.
    pub fn is_malicious(&self) -> bool {
        self.id.starts_with("MAL-") || self.aliases.iter().any(|a| a.starts_with("MAL-"))
    }
}

/// A cached lookup result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    schema: u32,
    purl: String,
    advisories: Vec<Advisory>,
    fetched_at_unix: i64,
}

/// OSV client with an on-disk cache.
pub struct OsvClient {
    cache_dir: PathBuf,
    offline: bool,
    timeout: Duration,
}

impl OsvClient {
    /// Build a client. `cache_dir` is created on first write.
    pub fn new(cache_dir: PathBuf, offline: bool) -> Self {
        Self {
            cache_dir,
            offline,
            timeout: Duration::from_secs(30),
        }
    }

    /// Default cache location: `~/.cache/n3tra/osv`.
    pub fn default_cache_dir() -> PathBuf {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(std::env::temp_dir)
            .join("n3tra/osv")
    }

    /// Look up advisories affecting exactly this package version.
    pub fn query(&self, purl: &Purl) -> Result<Vec<Advisory>, AdvisoryError> {
        // A package with no version cannot be matched. The caller turns this into
        // a coverage gap rather than an empty (clean-looking) result.
        let Some(version) = purl.version() else {
            return Err(AdvisoryError::Malformed {
                purl: purl.to_string(),
                detail: "no version to match against".into(),
            });
        };

        if let Some(cached) = self.read_cache(purl) {
            return Ok(cached);
        }

        if self.offline {
            return Err(AdvisoryError::OfflineCacheMiss(purl.to_string()));
        }

        let Some(ecosystem) = osv_ecosystem(purl) else {
            return Err(AdvisoryError::Malformed {
                purl: purl.to_string(),
                detail: format!("no OSV ecosystem mapping for type `{}`", purl.ty()),
            });
        };

        let body = serde_json::json!({
            "version": version,
            "package": { "name": osv_name(purl), "ecosystem": ecosystem }
        });

        let response = ureq::post(OSV_QUERY_URL)
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .send_json(&body)
            .map_err(|e| AdvisoryError::Transport {
                purl: purl.to_string(),
                detail: e.to_string(),
            })?
            .body_mut()
            .read_json::<serde_json::Value>()
            .map_err(|e| AdvisoryError::Malformed {
                purl: purl.to_string(),
                detail: e.to_string(),
            })?;

        let advisories = parse_osv_response(&response);
        self.write_cache(purl, &advisories);
        Ok(advisories)
    }

    /// Look up advisories for many packages at once.
    ///
    /// One HTTP request per 500 packages instead of one per package. This is not
    /// a micro-optimization: serially querying a 2400-package lockfile took
    /// minutes and blew the Stage 0 budget outright, which is the kind of cost
    /// that gets a CI step deleted.
    ///
    /// `querybatch` returns only vulnerability *ids*, so full records are then
    /// fetched once per unique id — typically far fewer requests than packages,
    /// since one advisory usually affects many packages.
    ///
    /// Returns `(results, errors)`. A package that could not be checked appears
    /// in `errors`, never as an empty (clean-looking) result — INV-5.
    pub fn query_many(
        &self,
        purls: &[Purl],
    ) -> (BTreeMap<String, Vec<Advisory>>, Vec<AdvisoryError>) {
        let mut results: BTreeMap<String, Vec<Advisory>> = BTreeMap::new();
        let mut errors = Vec::new();
        let mut pending: Vec<&Purl> = Vec::new();

        for purl in purls {
            if purl.version().is_none() {
                errors.push(AdvisoryError::Malformed {
                    purl: purl.to_string(),
                    detail: "no version to match against".into(),
                });
                continue;
            }
            if let Some(cached) = self.read_cache(purl) {
                results.insert(purl.to_string(), cached);
                continue;
            }
            if self.offline {
                errors.push(AdvisoryError::OfflineCacheMiss(purl.to_string()));
                continue;
            }
            if osv_ecosystem(purl).is_none() {
                errors.push(AdvisoryError::Malformed {
                    purl: purl.to_string(),
                    detail: format!("no OSV ecosystem mapping for type `{}`", purl.ty()),
                });
                continue;
            }
            pending.push(purl);
        }

        for chunk in pending.chunks(BATCH_SIZE) {
            match self.batch_ids(chunk) {
                Ok(ids_per_purl) => {
                    // Fetch each distinct advisory once, in parallel. One
                    // advisory usually affects many packages, so the distinct
                    // set is far smaller than the package count — and fetching
                    // them serially was the bulk of a 24s cold run.
                    let distinct: BTreeSet<String> =
                        ids_per_purl.iter().flatten().cloned().collect();
                    let fetched = self.fetch_vulns_parallel(&distinct);

                    for (purl, ids) in chunk.iter().zip(ids_per_purl) {
                        let mut advisories = Vec::new();
                        let mut failed = false;
                        for id in &ids {
                            match fetched.get(id) {
                                Some(Ok(a)) => advisories.push(a.clone()),
                                Some(Err(detail)) => {
                                    // A known-present advisory we could not fetch
                                    // is a hole, not an absence.
                                    errors.push(AdvisoryError::Transport {
                                        purl: id.clone(),
                                        detail: detail.clone(),
                                    });
                                    failed = true;
                                }
                                None => failed = true,
                            }
                        }
                        if failed {
                            continue;
                        }
                        advisories.sort_by(|a, b| {
                            b.cvss_score
                                .unwrap_or(-1.0)
                                .partial_cmp(&a.cvss_score.unwrap_or(-1.0))
                                .unwrap_or(std::cmp::Ordering::Equal)
                                .then_with(|| a.id.cmp(&b.id))
                        });
                        self.write_cache(purl, &advisories);
                        results.insert(purl.to_string(), advisories);
                    }
                }
                Err(e) => {
                    // Whole batch failed: every package in it is unchecked.
                    let detail = e.to_string();
                    for purl in chunk {
                        errors.push(AdvisoryError::Transport {
                            purl: purl.to_string(),
                            detail: detail.clone(),
                        });
                    }
                }
            }
        }

        (results, errors)
    }

    /// One `querybatch` call: package -> list of advisory ids.
    fn batch_ids(&self, purls: &[&Purl]) -> Result<Vec<Vec<String>>, AdvisoryError> {
        let queries: Vec<serde_json::Value> = purls
            .iter()
            .map(|purl| {
                serde_json::json!({
                    "version": purl.version().unwrap_or_default(),
                    "package": {
                        "name": osv_name(purl),
                        "ecosystem": osv_ecosystem(purl).unwrap_or_default(),
                    }
                })
            })
            .collect();

        let label = purls
            .first()
            .map(|p| format!("batch of {} starting at {p}", purls.len()))
            .unwrap_or_else(|| "empty batch".to_string());

        let response = ureq::post(OSV_QUERYBATCH_URL)
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .send_json(serde_json::json!({ "queries": queries }))
            .map_err(|e| AdvisoryError::Transport {
                purl: label.clone(),
                detail: e.to_string(),
            })?
            .body_mut()
            .read_json::<serde_json::Value>()
            .map_err(|e| AdvisoryError::Malformed {
                purl: label.clone(),
                detail: e.to_string(),
            })?;

        let results = response
            .get("results")
            .and_then(|r| r.as_array())
            .ok_or_else(|| AdvisoryError::Malformed {
                purl: label.clone(),
                detail: "querybatch response had no `results` array".into(),
            })?;

        // A short results array would silently mis-align packages with their
        // advisories, which is worse than an error.
        if results.len() != purls.len() {
            return Err(AdvisoryError::Malformed {
                purl: label,
                detail: format!(
                    "querybatch returned {} results for {} queries",
                    results.len(),
                    purls.len()
                ),
            });
        }

        Ok(results
            .iter()
            .map(|r| {
                r.get("vulns")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.get("id").and_then(|i| i.as_str()))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect())
    }

    /// Fetch many advisories concurrently, bounded to a small pool.
    ///
    /// Plain OS threads rather than an async runtime: `ureq` is blocking by
    /// design, and pulling in tokio for this would cost far more dependency
    /// budget than the concurrency is worth.
    fn fetch_vulns_parallel(
        &self,
        ids: &BTreeSet<String>,
    ) -> BTreeMap<String, Result<Advisory, String>> {
        // 16 rather than 8: the work is network-bound, not CPU-bound, and the
        // Stage 0 budget (10s for a 2000-package repo) left no margin at 8.
        const WORKERS: usize = 16;

        let queue: Vec<&String> = ids.iter().collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let out = std::sync::Mutex::new(BTreeMap::new());

        std::thread::scope(|scope| {
            for _ in 0..WORKERS.min(queue.len().max(1)) {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(id) = queue.get(i) else {
                        break;
                    };
                    let result = self.vuln_by_id(id).map_err(|e| e.to_string());
                    if let Ok(mut guard) = out.lock() {
                        guard.insert((*id).clone(), result);
                    }
                });
            }
        });

        out.into_inner().unwrap_or_default()
    }

    /// Fetch one advisory by id, memoized on disk.
    ///
    /// One advisory typically affects many packages, so this cache turns an
    /// O(packages) fetch into O(distinct advisories).
    fn vuln_by_id(&self, id: &str) -> Result<Advisory, AdvisoryError> {
        let path = self.vuln_cache_path(id);
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(a) = serde_json::from_str::<Advisory>(&text) {
                return Ok(a);
            }
        }
        if self.offline {
            return Err(AdvisoryError::OfflineCacheMiss(id.to_string()));
        }

        let value = ureq::get(&format!("{OSV_VULN_URL}/{id}"))
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .call()
            .map_err(|e| AdvisoryError::Transport {
                purl: id.to_string(),
                detail: e.to_string(),
            })?
            .body_mut()
            .read_json::<serde_json::Value>()
            .map_err(|e| AdvisoryError::Malformed {
                purl: id.to_string(),
                detail: e.to_string(),
            })?;

        let advisory = parse_vuln(&value);
        if std::fs::create_dir_all(&self.cache_dir).is_ok() {
            if let Ok(json) = serde_json::to_string(&advisory) {
                let _ = std::fs::write(path, json);
            }
        }
        Ok(advisory)
    }

    fn vuln_cache_path(&self, id: &str) -> PathBuf {
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.cache_dir.join(format!("vuln-{safe}.json"))
    }

    fn cache_path(&self, purl: &Purl) -> PathBuf {
        self.cache_dir.join(format!("{}.json", cache_key(purl)))
    }

    fn read_cache(&self, purl: &Purl) -> Option<Vec<Advisory>> {
        let text = std::fs::read_to_string(self.cache_path(purl)).ok()?;
        let entry: CacheEntry = serde_json::from_str(&text).ok()?;
        // A schema or identity mismatch means refetch, never a wrong answer.
        (entry.schema == CACHE_SCHEMA && entry.purl == purl.to_string()).then_some(entry.advisories)
    }

    fn write_cache(&self, purl: &Purl, advisories: &[Advisory]) {
        let entry = CacheEntry {
            schema: CACHE_SCHEMA,
            purl: purl.to_string(),
            advisories: advisories.to_vec(),
            fetched_at_unix: now_unix(),
        };
        if std::fs::create_dir_all(&self.cache_dir).is_err() {
            return;
        }
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(self.cache_path(purl), json);
        }
    }

    /// Number of entries currently cached.
    pub fn cache_size(&self) -> usize {
        std::fs::read_dir(&self.cache_dir)
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0)
    }

    /// The cache directory in use.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

/// Filesystem-safe cache key. PURLs contain `/`, `@`, and `:`.
fn cache_key(purl: &Purl) -> String {
    purl.to_string()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The package name as OSV spells it: scoped/namespaced ecosystems keep the
/// namespace as part of the name.
pub fn osv_name(purl: &Purl) -> String {
    match purl.namespace() {
        Some(ns) if matches!(purl.ty(), "npm" | "golang" | "maven" | "composer") => {
            format!("{ns}/{}", purl.name())
        }
        _ => purl.name().to_string(),
    }
}

/// Map a PURL type onto an OSV ecosystem name.
///
/// Returns `None` rather than guessing: querying the wrong ecosystem returns an
/// empty result set, which would look exactly like "no vulnerabilities".
pub fn osv_ecosystem(purl: &Purl) -> Option<String> {
    Some(match purl.ty() {
        "pypi" => "PyPI".to_string(),
        "npm" => "npm".to_string(),
        "cargo" => "crates.io".to_string(),
        "golang" => "Go".to_string(),
        "gem" => "RubyGems".to_string(),
        "maven" => "Maven".to_string(),
        "nuget" => "NuGet".to_string(),
        "composer" => "Packagist".to_string(),
        "hex" => "Hex".to_string(),
        "apk" | "alpine" => "Alpine".to_string(),
        "deb" => match purl.namespace() {
            Some("debian") => "Debian".to_string(),
            Some("ubuntu") => "Ubuntu".to_string(),
            // An unattributed deb package cannot be routed to a feed.
            _ => return None,
        },
        _ => return None,
    })
}

/// Extract advisories from an OSV `/v1/query` response.
pub fn parse_osv_response(response: &serde_json::Value) -> Vec<Advisory> {
    let Some(vulns) = response.get("vulns").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out: Vec<Advisory> = vulns.iter().map(parse_vuln).collect();
    out.sort_by(|a, b| {
        b.cvss_score
            .unwrap_or(-1.0)
            .partial_cmp(&a.cvss_score.unwrap_or(-1.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn parse_vuln(vuln: &serde_json::Value) -> Advisory {
    let id = vuln
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let aliases: Vec<String> = vuln
        .get("aliases")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Prefer the highest-versioned CVSS vector present.
    let cvss = vuln
        .get("severity")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("score").and_then(|v| v.as_str()))
                .filter_map(Cvss::parse)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let scored = cvss
        .iter()
        .find(|c| c.score.is_some())
        .or_else(|| cvss.first());

    let fixed_versions = collect_fixed_versions(vuln);

    let is_mal = id.starts_with("MAL-") || aliases.iter().any(|a| a.starts_with("MAL-"));
    let severity = if is_mal {
        Severity::Malicious
    } else {
        scored
            .and_then(|c| c.severity())
            .or_else(|| label_severity(vuln))
            .unwrap_or(Severity::Medium)
    };

    Advisory {
        id,
        aliases,
        summary: vuln
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        cvss_vector: scored.map(|c| c.vector.clone()),
        cvss_score: scored.and_then(|c| c.score),
        severity,
        fixed_versions,
        references: vuln
            .get("references")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Fall back to a textual severity label when no scorable vector exists (common
/// for v4-only and for distro advisories).
fn label_severity(vuln: &serde_json::Value) -> Option<Severity> {
    let label = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|v| v.as_str())?;
    Some(match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => return None,
    })
}

/// Pull `fixed` events out of the affected ranges. These drive rung 1.
fn collect_fixed_versions(vuln: &serde_json::Value) -> Vec<String> {
    let mut fixed = Vec::new();
    let Some(affected) = vuln.get("affected").and_then(|v| v.as_array()) else {
        return fixed;
    };
    for entry in affected {
        let Some(ranges) = entry.get("ranges").and_then(|v| v.as_array()) else {
            continue;
        };
        for range in ranges {
            let Some(events) = range.get("events").and_then(|v| v.as_array()) else {
                continue;
            };
            for event in events {
                if let Some(v) = event.get("fixed").and_then(|v| v.as_str()) {
                    fixed.push(v.to_string());
                }
            }
        }
    }
    fixed.sort();
    fixed.dedup();
    fixed
}

/// Group advisories by package for reporting.
pub type AdvisoryMap = BTreeMap<String, Vec<Advisory>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn purl(s: &str) -> Purl {
        Purl::parse(s).expect("test purl")
    }

    #[test]
    fn ecosystem_mapping() {
        assert_eq!(
            osv_ecosystem(&purl("pkg:pypi/django@4.2")).as_deref(),
            Some("PyPI")
        );
        assert_eq!(
            osv_ecosystem(&purl("pkg:npm/left-pad@1.0")).as_deref(),
            Some("npm")
        );
        assert_eq!(
            osv_ecosystem(&purl("pkg:cargo/serde@1.0")).as_deref(),
            Some("crates.io")
        );
        assert_eq!(
            osv_ecosystem(&purl("pkg:deb/debian/openssl@3.0")).as_deref(),
            Some("Debian")
        );
        assert_eq!(
            osv_ecosystem(&purl("pkg:deb/ubuntu/openssl@3.0")).as_deref(),
            Some("Ubuntu")
        );
    }

    // Guessing a feed for an unattributed deb package would return an empty
    // result set, which is indistinguishable from "no vulnerabilities".
    #[test]
    fn unattributed_deb_has_no_ecosystem() {
        assert_eq!(osv_ecosystem(&purl("pkg:deb/openssl@3.0")), None);
        assert_eq!(osv_ecosystem(&purl("pkg:generic/thing@1.0")), None);
    }

    #[test]
    fn parses_a_realistic_osv_response() {
        let raw = serde_json::json!({"vulns": [{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2024-1234"],
            "summary": "Remote code execution",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.31.1"}
            ]}]}],
            "references": [{"type": "ADVISORY", "url": "https://example.com/a"}]
        }]});

        let advisories = parse_osv_response(&raw);
        assert_eq!(advisories.len(), 1);
        let a = advisories.first().expect("one advisory");
        assert_eq!(a.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(a.cvss_score, Some(9.8));
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.fixed_versions, ["2.31.1"]);
        assert!(!a.is_malicious());
    }

    // MAL- is a distinct class, not a CVSS band: "this package is hostile" must
    // never be summed with "this package has a flaw".
    #[test]
    fn mal_advisories_get_their_own_severity_class() {
        let raw = serde_json::json!({"vulns": [{
            "id": "MAL-2024-0001",
            "summary": "Malicious package"
        }]});
        let advisories = parse_osv_response(&raw);
        let a = advisories.first().expect("one advisory");
        assert!(a.is_malicious());
        assert_eq!(a.severity, Severity::Malicious);
        assert!(
            !a.severity.baselineable(),
            "MAL findings must not be baselineable"
        );
    }

    #[test]
    fn mal_detected_via_alias_too() {
        let raw = serde_json::json!({"vulns": [{
            "id": "GHSA-aaaa", "aliases": ["MAL-2024-9999"]
        }]});
        let a = parse_osv_response(&raw);
        assert_eq!(a.first().map(|a| a.severity), Some(Severity::Malicious));
    }

    #[test]
    fn falls_back_to_severity_label_when_no_scorable_vector() {
        let raw = serde_json::json!({"vulns": [{
            "id": "GHSA-v4only",
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "database_specific": {"severity": "HIGH"}
        }]});
        let a = parse_osv_response(&raw);
        let a = a.first().expect("one advisory");
        assert_eq!(
            a.cvss_score, None,
            "v4 must not be given a fabricated score"
        );
        assert_eq!(a.severity, Severity::High, "label should still classify it");
    }

    #[test]
    fn empty_response_yields_no_advisories() {
        assert!(parse_osv_response(&serde_json::json!({})).is_empty());
        assert!(parse_osv_response(&serde_json::json!({"vulns": []})).is_empty());
    }

    #[test]
    fn advisories_sort_most_severe_first() {
        let raw = serde_json::json!({"vulns": [
            {"id": "low", "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]},
            {"id": "crit", "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        ]});
        let ids: Vec<_> = parse_osv_response(&raw).into_iter().map(|a| a.id).collect();
        assert_eq!(ids, ["crit", "low"]);
    }

    // INV-5: offline plus cache miss is an error the caller turns into a gap.
    // It must never present as an empty, clean result.
    #[test]
    fn offline_cache_miss_is_an_error_not_an_empty_result() {
        let dir = std::env::temp_dir().join(format!("n3t-osv-empty-{}", std::process::id()));
        let client = OsvClient::new(dir, true);
        let err = client.query(&purl("pkg:pypi/django@4.2.0"));
        assert!(matches!(err, Err(AdvisoryError::OfflineCacheMiss(_))));
    }

    #[test]
    fn unversioned_package_is_an_error() {
        let dir = std::env::temp_dir().join("n3t-osv-unversioned");
        let client = OsvClient::new(dir, true);
        assert!(matches!(
            client.query(&purl("pkg:pypi/django")),
            Err(AdvisoryError::Malformed { .. })
        ));
    }

    #[test]
    fn cache_round_trips() {
        let dir = std::env::temp_dir().join(format!("n3t-osv-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let client = OsvClient::new(dir.clone(), true);
        let p = purl("pkg:npm/left-pad@1.3.0");

        let advisories = vec![Advisory {
            id: "GHSA-test".into(),
            aliases: vec![],
            summary: "test".into(),
            cvss_vector: None,
            cvss_score: Some(5.0),
            severity: Severity::Medium,
            fixed_versions: vec!["1.3.1".into()],
            references: vec![],
        }];
        client.write_cache(&p, &advisories);

        // Offline now succeeds, because the cache has it.
        assert_eq!(client.query(&p).expect("cached"), advisories);
        assert_eq!(client.cache_size(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_keys_are_filesystem_safe() {
        let key = cache_key(&purl("pkg:npm/%40angular/core@17.0.0"));
        assert!(!key.contains('/'), "key must not contain a path separator");
        assert!(!key.contains(':'));
        assert!(key.contains("angular"));
    }
}
