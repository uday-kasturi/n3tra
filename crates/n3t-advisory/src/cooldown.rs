//! Version cooldown: flag dependencies published within the last N days.
//!
//! Cheap, requires no data moat, and empirically effective against
//! maintainer-compromise attacks that publish and get yanked within days —
//! precisely the class (Shai-Hulud, event-stream) that build observation cannot
//! see, because nothing anomalous happens during the build at all.
//!
//! This is a *policy*, not evidence. A young package is not a malicious one, and
//! the reporting must say so.

use n3t_core::purl::Purl;

/// Publication metadata for one package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishInfo {
    /// ISO 8601 timestamp as the registry reported it.
    pub published_at: String,
    /// Whole days between publication and now.
    pub age_days: i64,
}

/// Why a cooldown check could not be completed.
#[derive(Debug, thiserror::Error)]
pub enum CooldownError {
    /// No registry client for this ecosystem. Reports `unknown`, not `clean`.
    #[error("no registry publish-date source for `{0}`")]
    UnsupportedEcosystem(String),
    /// Network failure.
    #[error("querying registry for {purl}: {detail}")]
    Transport {
        /// Package queried.
        purl: String,
        /// What went wrong.
        detail: String,
    },
    /// The registry answered but not with a date we could read.
    #[error("no publish date for {0} in registry response")]
    NoPublishDate(String),
}

/// Registry client for publish dates.
pub struct RegistryClient {
    offline: bool,
    timeout: std::time::Duration,
}

impl RegistryClient {
    /// Build a client.
    pub fn new(offline: bool) -> Self {
        Self {
            offline,
            timeout: std::time::Duration::from_secs(20),
        }
    }

    /// When was this exact version published?
    pub fn publish_info(&self, purl: &Purl, now_unix: i64) -> Result<PublishInfo, CooldownError> {
        if self.offline {
            return Err(CooldownError::Transport {
                purl: purl.to_string(),
                detail: "offline".into(),
            });
        }
        let Some(version) = purl.version() else {
            return Err(CooldownError::NoPublishDate(purl.to_string()));
        };

        let published_at = match purl.ty() {
            "npm" => self.npm_publish_date(purl, version)?,
            "pypi" => self.pypi_publish_date(purl, version)?,
            other => return Err(CooldownError::UnsupportedEcosystem(other.to_string())),
        };

        let age_days = age_in_days(&published_at, now_unix)
            .ok_or_else(|| CooldownError::NoPublishDate(purl.to_string()))?;

        Ok(PublishInfo {
            published_at,
            age_days,
        })
    }

    fn get_json(&self, url: &str, purl: &Purl) -> Result<serde_json::Value, CooldownError> {
        ureq::get(url)
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .call()
            .map_err(|e| CooldownError::Transport {
                purl: purl.to_string(),
                detail: e.to_string(),
            })?
            .body_mut()
            .read_json::<serde_json::Value>()
            .map_err(|e| CooldownError::Transport {
                purl: purl.to_string(),
                detail: e.to_string(),
            })
    }

    fn npm_publish_date(&self, purl: &Purl, version: &str) -> Result<String, CooldownError> {
        let name = match purl.namespace() {
            Some(ns) => format!("{ns}/{}", purl.name()),
            None => purl.name().to_string(),
        };
        let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2F"));
        let doc = self.get_json(&url, purl)?;
        doc.get("time")
            .and_then(|t| t.get(version))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CooldownError::NoPublishDate(purl.to_string()))
    }

    fn pypi_publish_date(&self, purl: &Purl, version: &str) -> Result<String, CooldownError> {
        let url = format!("https://pypi.org/pypi/{}/{}/json", purl.name(), version);
        let doc = self.get_json(&url, purl)?;
        doc.get("urls")
            .and_then(|u| u.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("upload_time_iso_8601"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CooldownError::NoPublishDate(purl.to_string()))
    }
}

/// Whole days between an ISO 8601 timestamp and `now_unix`.
///
/// Only the date portion is used: sub-day precision is noise for a policy
/// measured in days, and parsing it would mean handling every timezone spelling
/// registries emit.
pub fn age_in_days(iso: &str, now_unix: i64) -> Option<i64> {
    let date = iso.split(['T', ' ']).next()?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;

    let published_days = days_from_civil(year, month, day)?;
    let now_days = now_unix.div_euclid(86_400);
    Some(now_days - published_days)
}

/// Days from the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Does this package fall inside the cooldown window?
pub fn is_within_cooldown(info: &PublishInfo, min_age_days: i64) -> bool {
    info.age_days < min_age_days
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2024-01-15T00:00:00Z
    const JAN_15_2024: i64 = 1_705_276_800;

    #[test]
    fn civil_date_conversion_matches_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11017));
        assert_eq!(days_from_civil(2024, 1, 15), Some(19737));
    }

    #[test]
    fn leap_year_boundary() {
        let feb29 = days_from_civil(2024, 2, 29).expect("2024 is a leap year");
        let mar01 = days_from_civil(2024, 3, 1).expect("valid");
        assert_eq!(mar01 - feb29, 1);
    }

    #[test]
    fn age_computed_from_iso_timestamps() {
        assert_eq!(
            age_in_days("2024-01-15T10:30:00.000Z", JAN_15_2024),
            Some(0)
        );
        assert_eq!(age_in_days("2024-01-05T00:00:00Z", JAN_15_2024), Some(10));
        assert_eq!(age_in_days("2023-01-15", JAN_15_2024), Some(365));
    }

    #[test]
    fn handles_registry_timestamp_spellings() {
        for stamp in [
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00Z",
            "2024-01-01 00:00:00",
            "2024-01-01",
        ] {
            assert_eq!(age_in_days(stamp, JAN_15_2024), Some(14), "{stamp}");
        }
    }

    #[test]
    fn malformed_timestamps_return_none_not_panic() {
        for bad in ["", "not-a-date", "2024", "2024-13-01", "2024-01-99", "----"] {
            assert_eq!(age_in_days(bad, JAN_15_2024), None, "{bad}");
        }
    }

    #[test]
    fn cooldown_window_is_exclusive_at_the_boundary() {
        let fresh = PublishInfo {
            published_at: "x".into(),
            age_days: 3,
        };
        let aged = PublishInfo {
            published_at: "x".into(),
            age_days: 7,
        };
        assert!(is_within_cooldown(&fresh, 7));
        assert!(
            !is_within_cooldown(&aged, 7),
            "a package exactly at the threshold has cooled"
        );
    }

    #[test]
    fn unsupported_ecosystem_is_an_error_not_a_pass() {
        let client = RegistryClient::new(false);
        let purl = Purl::parse("pkg:deb/debian/openssl@3.0").expect("purl");
        assert!(matches!(
            client.publish_info(&purl, JAN_15_2024),
            Err(CooldownError::UnsupportedEcosystem(_))
        ));
    }
}
