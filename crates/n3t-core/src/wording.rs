//! INV-9: usage claims are scoped to one build, in every output surface.
//!
//! A reader who sees "unused dependency" will conclude it is safe to delete in
//! production. Build-time evidence does not support that, and for a
//! containerized interpreted-language service it is close to *anti-correlated*
//! with necessity: the database driver and HTTP client are by definition not
//! loaded during `docker build`, they load when the container starts serving.
//!
//! So the prohibited phrasings are checked mechanically rather than left to
//! reviewer discipline.

/// The only approved phrasing for a package that was never read during the build.
pub const NOT_LOADED: &str = "not loaded during this build";

/// The approved phrasing for host mode, where there is no build to scope to and
/// the claim is therefore weaker still.
pub const NOT_LOADED_HOST: &str = "not loaded since n3tra started watching";

/// Phrasings that invite a reader to infer runtime safety from build-time
/// evidence. Checked case-insensitively against every rendered report.
pub const PROHIBITED: &[&str] = &[
    "unused",
    "not used",
    "never used",
    "safe to remove",
    "safe to delete",
    "can be removed",
    "dead dependency",
    "unnecessary dependency",
];

/// A prohibited phrase found in report text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordingViolation {
    /// The prohibited phrase.
    pub phrase: &'static str,
    /// Byte offset where it occurred.
    pub at: usize,
}

/// Scan rendered report text for prohibited phrasings.
///
/// Report renderers call this in debug builds and tests call it over every
/// template. Empty result means the text is compliant.
pub fn check(text: &str) -> Vec<WordingViolation> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    for phrase in PROHIBITED {
        let mut from = 0;
        while let Some(rel) = lower.get(from..).and_then(|s| s.find(phrase)) {
            let at = from + rel;
            found.push(WordingViolation { phrase, at });
            from = at + phrase.len();
        }
    }
    found.sort_by_key(|v| v.at);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_phrasings_are_compliant() {
        assert!(check(NOT_LOADED).is_empty());
        assert!(check(NOT_LOADED_HOST).is_empty());
    }

    #[test]
    fn catches_the_tempting_shorthand() {
        assert_eq!(check("3 unused dependencies").len(), 1);
        assert_eq!(check("This package is safe to remove.").len(), 1);
        assert_eq!(check("boto3 was never used").len(), 1);
    }

    #[test]
    fn is_case_insensitive() {
        assert_eq!(check("UNUSED").len(), 1);
        assert_eq!(check("Safe To Delete").len(), 1);
    }

    #[test]
    fn reports_every_occurrence_in_order() {
        let v = check("unused and also unused");
        assert_eq!(v.len(), 2);
        assert!(v.first().map(|x| x.at) < v.get(1).map(|x| x.at));
    }

    #[test]
    fn clean_text_passes() {
        assert!(check("requests@2.31.0 was not loaded during this build").is_empty());
    }
}
