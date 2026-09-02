//! Fuzz the advisory-response and CVSS parsers.
//!
//! OSV responses and the on-disk advisory cache both cross a trust boundary: the
//! first is remote data, the second is a file any local process can rewrite. A
//! panic here takes down the audit after the inventory already succeeded.
//!
//! CVSS vectors get a second property beyond no-panic: any score produced must
//! be within the specification's 0.0–10.0 range. A score outside it would flow
//! straight into `--cvss` threshold comparisons and silently change what gates.
#![no_main]

use libfuzzer_sys::fuzz_target;
use n3t_advisory::cvss::Cvss;
use n3t_advisory::osv::parse_osv_response;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };

    if selector % 2 == 0 {
        // OSV response shapes.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let advisories = parse_osv_response(&value);
            for a in &advisories {
                if let Some(score) = a.cvss_score {
                    assert!(
                        (0.0..=10.0).contains(&score),
                        "CVSS score {score} outside the specified 0.0-10.0 range"
                    );
                    assert!(!score.is_nan(), "CVSS score was NaN");
                }
            }
        }
    } else if let Some(cvss) = Cvss::parse(text) {
        if let Some(score) = cvss.score {
            assert!(
                (0.0..=10.0).contains(&score),
                "CVSS score {score} outside 0.0-10.0 for vector {:?}",
                cvss.vector
            );
            assert!(!score.is_nan(), "CVSS score was NaN for {:?}", cvss.vector);
            // A scored vector must classify; a band with no score must not.
            assert!(cvss.severity().is_some());
        }
    }
});
