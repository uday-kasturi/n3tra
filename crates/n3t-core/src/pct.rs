//! Percent-encoding for PURL components.
//!
//! Hand-rolled rather than pulled from a crate: this is ~40 lines and the
//! dependency budget (Stage 0) is a hard CI gate. See `docs/DEPENDENCIES.md`.

/// Characters left literal in PURL name/namespace/version components.
///
/// `+` and `:` are deliberately safe: PEP 440 local version segments
/// (`1.0+local.1`) and Debian epochs (`1:2.3-4`) are far more legible unencoded,
/// and both are unambiguous in these positions.
fn is_component_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b':')
}

/// Characters left literal in qualifier values. Narrower than component-safe:
/// `&` and `=` are structural here, and `:` shows up in VCS URLs.
fn is_qualifier_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b':' | b'/')
}

fn encode_with(s: &str, safe: fn(u8) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit((b & 0x0f) as u32, 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

/// Percent-encode a PURL name, namespace segment, or version.
pub fn encode_component(s: &str) -> String {
    encode_with(s, is_component_safe)
}

/// Percent-encode a PURL qualifier value.
pub fn encode_qualifier(s: &str) -> String {
    encode_with(s, is_qualifier_safe)
}

/// Percent-decode. Invalid escapes are preserved literally rather than erroring:
/// a lockfile in the wild containing a bare `%` is malformed input we still want
/// to attribute, not a reason to abort a scan (Stage 0: zero panics, and a
/// malformed manifest must degrade, not crash).
pub fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(&b'%') => {
                let hi = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16));
                let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(((hi << 4) | lo) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            Some(&b) => {
                out.push(b);
                i += 1;
            }
            None => break,
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_ascii() {
        for s in ["core", "@angular", "1.0+local.1", "1:2.3-4", "a b", "100%"] {
            assert_eq!(decode(&encode_component(s)), s, "failed on {s:?}");
        }
    }

    #[test]
    fn encodes_purl_structural_chars() {
        assert_eq!(encode_component("@angular"), "%40angular");
        assert_eq!(encode_component("a/b"), "a%2Fb");
        assert_eq!(encode_component("a?b"), "a%3Fb");
        assert_eq!(encode_component("a#b"), "a%23b");
        assert_eq!(encode_component("a%b"), "a%25b");
    }

    #[test]
    fn leaves_epoch_and_local_version_legible() {
        assert_eq!(encode_component("1:2.3-4"), "1:2.3-4");
        assert_eq!(encode_component("1.0+local.1"), "1.0+local.1");
    }

    #[test]
    fn malformed_escapes_do_not_panic() {
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("%4"), "%4");
        assert_eq!(decode("%"), "%");
    }

    #[test]
    fn decodes_multibyte() {
        assert_eq!(decode("caf%C3%A9"), "café");
    }
}
