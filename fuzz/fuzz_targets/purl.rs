//! Fuzz PURL parsing and its normalization invariant.
//!
//! PURL strings arrive from lockfiles, advisory feeds, and cached data, all of
//! which cross a trust boundary. Two properties are asserted:
//!
//! 1. **No panic.** PURL parsing sits under every other code path.
//! 2. **Normalization is idempotent.** `parse(serialize(parse(s))) == parse(s)`.
//!    This is not cosmetic: graph node identity and advisory-cache keys are the
//!    canonical string, so an unstable normalization would silently split one
//!    package into two nodes and miss advisories for whichever half lost.
#![no_main]

use libfuzzer_sys::fuzz_target;
use n3t_core::purl::Purl;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(once) = Purl::parse(text) else {
        return;
    };

    let canonical = once.to_string();
    let twice = match Purl::parse(&canonical) {
        Ok(p) => p,
        Err(e) => panic!("canonical form failed to reparse: {canonical:?}: {e}"),
    };

    assert_eq!(once, twice, "normalization not idempotent for input {text:?}");
    assert_eq!(
        canonical,
        twice.to_string(),
        "canonical string unstable for input {text:?}"
    );
});
