//! Package URL (PURL) — the single identity space across every ecosystem.
//!
//! This is the type that makes n3tra ecosystem-agnostic: one identifier, one
//! advisory lookup path, N thin parsers behind a trait. Adding an ecosystem must
//! never require a change here.
//!
//! Spec: <https://github.com/package-url/purl-spec>

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pct;

/// Why a PURL string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PurlError {
    /// The string did not begin with the required `pkg:` scheme.
    #[error("missing `pkg:` scheme")]
    MissingScheme,
    /// The package type (the segment right after `pkg:`) was empty.
    #[error("empty package type")]
    EmptyType,
    /// The package name was empty.
    #[error("empty package name")]
    EmptyName,
    /// The type contained characters outside the permitted set.
    #[error("invalid package type {0:?}")]
    InvalidType(String),
}

/// A parsed, normalized Package URL.
///
/// Construction always normalizes, so two PURLs that denote the same package
/// compare equal and hash equal regardless of how they were written. That
/// property is load-bearing: it is what lets advisory matching and graph node
/// identity be a plain map lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Purl {
    ty: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
    qualifiers: BTreeMap<String, String>,
    subpath: Option<String>,
}

impl Purl {
    /// Parse and normalize a PURL string.
    pub fn parse(input: &str) -> Result<Self, PurlError> {
        let s = input.trim();

        // Scheme is case-insensitive per spec.
        let rest = s
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("pkg:"))
            .and_then(|_| s.get(4..))
            .ok_or(PurlError::MissingScheme)?;

        // `pkg://npm/foo` is tolerated by the spec; the slashes carry no meaning.
        let rest = rest.trim_start_matches('/');

        let (rest, subpath) = split_last(rest, '#');
        let (rest, qualifiers) = split_last(rest, '?');
        let (rest, version) = split_last(rest, '@');

        let mut segments = rest.split('/').filter(|seg| !seg.is_empty());
        let ty = segments
            .next()
            .ok_or(PurlError::EmptyType)?
            .to_ascii_lowercase();
        if ty.is_empty() {
            return Err(PurlError::EmptyType);
        }
        if !ty
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+'))
        {
            return Err(PurlError::InvalidType(ty));
        }

        let mut path: Vec<String> = segments.map(pct::decode).collect();
        let name = path.pop().ok_or(PurlError::EmptyName)?;
        if name.is_empty() {
            return Err(PurlError::EmptyName);
        }
        let namespace = if path.is_empty() {
            None
        } else {
            Some(path.join("/"))
        };

        Ok(Self::normalized(
            ty,
            namespace,
            name,
            version.map(pct::decode).filter(|v| !v.is_empty()),
            qualifiers.map(parse_qualifiers).unwrap_or_default(),
            subpath.map(normalize_subpath).filter(|s| !s.is_empty()),
        ))
    }

    /// Build a PURL from already-separated components, applying the same
    /// normalization `parse` applies. Ecosystem parsers use this rather than
    /// formatting a string and re-parsing it.
    pub fn new(
        ty: impl Into<String>,
        namespace: Option<String>,
        name: impl Into<String>,
        version: Option<String>,
    ) -> Result<Self, PurlError> {
        let ty = ty.into().to_ascii_lowercase();
        if ty.is_empty() {
            return Err(PurlError::EmptyType);
        }
        let name = name.into();
        if name.is_empty() {
            return Err(PurlError::EmptyName);
        }
        Ok(Self::normalized(
            ty,
            namespace,
            name,
            version,
            BTreeMap::new(),
            None,
        ))
    }

    fn normalized(
        ty: String,
        namespace: Option<String>,
        name: String,
        version: Option<String>,
        qualifiers: BTreeMap<String, String>,
        subpath: Option<String>,
    ) -> Self {
        // Type-specific normalization, per the PURL spec's per-type rules.
        // Versions are never normalized: version comparison is the ecosystem's
        // business, and mangling a version here would silently break advisory
        // range matching.
        let (namespace, name) = match ty.as_str() {
            "pypi" => (namespace, name.to_ascii_lowercase().replace('_', "-")),
            "npm" => (
                namespace.map(|n| n.to_ascii_lowercase()),
                name.to_ascii_lowercase(),
            ),
            "golang" | "github" | "bitbucket" => (
                namespace.map(|n| n.to_ascii_lowercase()),
                name.to_ascii_lowercase(),
            ),
            "deb" | "rpm" | "apk" | "alpine" | "cargo" | "gem" | "hex" => (
                namespace.map(|n| n.to_ascii_lowercase()),
                name.to_ascii_lowercase(),
            ),
            _ => (namespace, name),
        };

        // A namespace is a sequence of segments joined with `/`, but a segment
        // that decoded to contain a literal `/` (from `%2F`) makes the joined
        // form ambiguous: Display re-splits on `/`, so the segment boundaries
        // move and the canonical string no longer reparses to itself.
        //
        // Found by `cargo fuzz run purl` on `pkg:F/:%%2F/F`. Normalizing an
        // encoded slash into a real segment boundary makes the representation
        // canonical, and a namespace segment containing an encoded separator is
        // exotic enough that treating it as a separator is the sane reading.
        // Namespace segments arrive already decoded, so `flatten_path` must not
        // decode again (see its docs — `pct::decode` is not idempotent). Dot
        // segments are kept: a Go module path may legitimately contain them.
        let namespace = namespace.map(|ns| flatten_path(&ns, false));

        Self {
            ty,
            namespace: namespace.filter(|n| !n.is_empty()),
            name,
            version: version.filter(|v| !v.is_empty()),
            qualifiers,
            subpath,
        }
    }

    /// The package type, lowercased (`pypi`, `npm`, `deb`, ...).
    pub fn ty(&self) -> &str {
        &self.ty
    }
    /// The namespace (npm scope, Go module prefix, deb distro), if any.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    /// The package name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The version, if pinned.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    /// Qualifiers, sorted by key for deterministic serialization.
    pub fn qualifiers(&self) -> &BTreeMap<String, String> {
        &self.qualifiers
    }
    /// The subpath within the package, if any.
    pub fn subpath(&self) -> Option<&str> {
        self.subpath.as_deref()
    }

    /// The same package with its version stripped.
    ///
    /// Advisory matching is keyed on the versionless PURL, then version ranges
    /// are evaluated separately.
    pub fn without_version(&self) -> Self {
        Self {
            version: None,
            ..self.clone()
        }
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}", self.ty)?;
        if let Some(ns) = &self.namespace {
            for seg in ns.split('/') {
                write!(f, "/{}", pct::encode_component(seg))?;
            }
        }
        write!(f, "/{}", pct::encode_component(&self.name))?;
        if let Some(v) = &self.version {
            write!(f, "@{}", pct::encode_component(v))?;
        }
        if !self.qualifiers.is_empty() {
            f.write_str("?")?;
            for (i, (k, v)) in self.qualifiers.iter().enumerate() {
                if i > 0 {
                    f.write_str("&")?;
                }
                write!(f, "{}={}", k, pct::encode_qualifier(v))?;
            }
        }
        if let Some(sp) = &self.subpath {
            // Each segment is encoded independently, so `/` stays structural.
            //
            // Encoding here is not cosmetic. `Purl::parse` trims its input, so an
            // unencoded subpath ending in whitespace reparses to a *different*
            // PURL — `pkg:f/k# /` was found by the fuzzer producing a canonical
            // form that normalized to something else on the next pass. Since node
            // identity and the advisory cache are both keyed on this string, that
            // would silently split one package into two.
            f.write_str("#")?;
            for (i, seg) in sp.split('/').enumerate() {
                if i > 0 {
                    f.write_str("/")?;
                }
                f.write_str(&pct::encode_component(seg))?;
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for Purl {
    type Err = PurlError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Purl {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Purl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Purl::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Split once on the *last* occurrence of `sep`, returning `(head, tail)`.
fn split_last(s: &str, sep: char) -> (&str, Option<&str>) {
    match s.rsplit_once(sep) {
        Some((head, tail)) => (head, Some(tail)),
        None => (s, None),
    }
}

fn parse_qualifiers(s: &str) -> BTreeMap<String, String> {
    s.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k = k.trim().to_ascii_lowercase();
            let v = pct::decode(v);
            // Keys are written unencoded, so a key outside the spec's permitted
            // charset would not survive a round trip. Dropping it keeps the
            // canonical form stable; the alternative is an identity that changes
            // every time it is serialized.
            let key_ok = !k.is_empty()
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            // Per spec, a qualifier with an empty value is omitted entirely.
            (key_ok && !v.is_empty()).then_some((k, v))
        })
        .collect()
}

/// Decode a `/`-joined path, flattening any decoded `/` into a real separator.
///
/// Both the namespace and the subpath are sequences of percent-encoded segments
/// joined by `/`. If a segment decodes to something *containing* `/`, the joined
/// representation becomes ambiguous — `Display` re-splits on `/`, so the segment
/// boundaries move and the canonical string stops reparsing to itself.
///
/// The fuzzer found this twice, in both fields (`pkg:F/:%%2F/F` and
/// `pkg:F/F#%2F`). Flattening makes the stored form canonical, which is what
/// node identity and the advisory cache key both depend on.
/// Takes an **already-decoded** path and drops empty (and optionally dot)
/// segments, so a decoded `/` becomes a real boundary.
///
/// Decoding deliberately does not happen here. `pct::decode` is *not*
/// idempotent — `%%333` decodes to `%33`, which decodes again to `%3` — so a
/// helper that both decoded and flattened would corrupt any caller that had
/// already decoded. That was itself a fuzz find (`pkg:F/%%%3333/Ff`), caught
/// only because the idempotence property is asserted rather than assumed.
fn flatten_path(s: &str, drop_dot_segments: bool) -> String {
    s.split('/')
        .filter(|seg| !seg.is_empty() && !(drop_dot_segments && (*seg == "." || *seg == "..")))
        .collect::<Vec<_>>()
        .join("/")
}

/// Decode each raw subpath segment, then flatten.
///
/// Order matters: decoding first means a segment that decodes to contain `/`
/// (from `%2F`) turns into real segment boundaries rather than an ambiguous
/// joined string.
fn normalize_subpath(s: &str) -> String {
    let decoded = s.split('/').map(pct::decode).collect::<Vec<_>>().join("/");
    flatten_path(&decoded, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Purl {
        match Purl::parse(s) {
            Ok(v) => v,
            Err(e) => panic!("parse {s:?} failed: {e}"),
        }
    }

    #[test]
    fn parses_basic() {
        let purl = p("pkg:pypi/requests@2.31.0");
        assert_eq!(purl.ty(), "pypi");
        assert_eq!(purl.namespace(), None);
        assert_eq!(purl.name(), "requests");
        assert_eq!(purl.version(), Some("2.31.0"));
        assert_eq!(purl.to_string(), "pkg:pypi/requests@2.31.0");
    }

    // INV: npm scopes survive the round trip. `@` is structural in a PURL, so a
    // scope must be percent-encoded on output but read back identically.
    #[test]
    fn npm_scope_round_trips() {
        let purl = p("pkg:npm/%40angular/core@17.0.0");
        assert_eq!(purl.namespace(), Some("@angular"));
        assert_eq!(purl.name(), "core");
        assert_eq!(purl.version(), Some("17.0.0"));
        assert_eq!(purl.to_string(), "pkg:npm/%40angular/core@17.0.0");

        // The un-encoded spelling is what humans and some tools actually emit.
        assert_eq!(p("pkg:npm/@angular/core@17.0.0"), purl);
    }

    #[test]
    fn deb_epoch_version_preserved() {
        let purl = p("pkg:deb/debian/openssl@1:3.0.11-1~deb12u2");
        assert_eq!(purl.version(), Some("1:3.0.11-1~deb12u2"));
        assert_eq!(
            purl.to_string(),
            "pkg:deb/debian/openssl@1:3.0.11-1~deb12u2"
        );
    }

    #[test]
    fn pep440_local_version_preserved() {
        let purl = p("pkg:pypi/torch@2.1.0+cu118");
        assert_eq!(purl.version(), Some("2.1.0+cu118"));
        assert_eq!(purl.to_string(), "pkg:pypi/torch@2.1.0+cu118");
    }

    // PEP 503: PyPI names are case-insensitive and `_`/`-` are equivalent.
    // Getting this wrong means missing advisories on half of PyPI.
    #[test]
    fn pypi_name_normalization() {
        assert_eq!(p("pkg:pypi/Django@4.2"), p("pkg:pypi/django@4.2"));
        assert_eq!(
            p("pkg:pypi/typing_extensions@4.0"),
            p("pkg:pypi/typing-extensions@4.0")
        );
        assert_eq!(p("pkg:pypi/Zope_Interface@5.0").name(), "zope-interface");
    }

    // Versions must NOT be normalized — that is the ecosystem's business, and
    // mangling them here would silently break advisory range matching.
    #[test]
    fn version_case_is_never_normalized() {
        assert_eq!(p("pkg:pypi/foo@1.0.0-RC1").version(), Some("1.0.0-RC1"));
    }

    #[test]
    fn multi_segment_golang_namespace() {
        let purl = p("pkg:golang/github.com/gorilla/mux@1.8.0");
        assert_eq!(purl.namespace(), Some("github.com/gorilla"));
        assert_eq!(purl.name(), "mux");
        assert_eq!(purl.to_string(), "pkg:golang/github.com/gorilla/mux@1.8.0");
    }

    #[test]
    fn qualifiers_are_sorted_and_empty_dropped() {
        let purl = p("pkg:deb/debian/curl@7.88?os=linux&arch=amd64&empty=");
        assert_eq!(purl.qualifiers().len(), 2);
        assert_eq!(
            purl.to_string(),
            "pkg:deb/debian/curl@7.88?arch=amd64&os=linux"
        );
    }

    #[test]
    fn subpath_parsed_and_dot_segments_stripped() {
        let purl = p("pkg:golang/github.com/foo/bar@1.0#pkg/./sub/../inner");
        assert_eq!(purl.subpath(), Some("pkg/sub/inner"));
    }

    #[test]
    fn scheme_is_case_insensitive_and_slashes_tolerated() {
        assert_eq!(p("PKG:npm/left-pad@1.0.0"), p("pkg:npm/left-pad@1.0.0"));
        assert_eq!(p("pkg://npm/left-pad@1.0.0"), p("pkg:npm/left-pad@1.0.0"));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Purl::parse("npm/foo"), Err(PurlError::MissingScheme));
        assert_eq!(Purl::parse("pkg:"), Err(PurlError::EmptyType));
        assert_eq!(Purl::parse("pkg:npm"), Err(PurlError::EmptyName));
        assert!(matches!(
            Purl::parse("pkg:n!pm/foo"),
            Err(PurlError::InvalidType(_))
        ));
    }

    #[test]
    fn without_version_strips_only_version() {
        let purl = p("pkg:npm/%40angular/core@17.0.0");
        assert_eq!(
            purl.without_version().to_string(),
            "pkg:npm/%40angular/core"
        );
    }

    /// The real property. Arbitrary input does not round-trip (normalization is
    /// lossy by design), but normalization must be *idempotent*: canonical form
    /// reparsed must equal itself. If this ever fails, graph node identity and
    /// advisory-cache keys become unstable.
    #[test]
    fn normalization_is_idempotent() {
        let cases = [
            "pkg:pypi/Django@4.2",
            "pkg:npm/@angular/core@17.0.0",
            "pkg:npm/%40angular/core@17.0.0",
            "pkg:deb/debian/openssl@1:3.0.11-1~deb12u2",
            "pkg:pypi/torch@2.1.0+cu118",
            "pkg:golang/github.com/gorilla/mux@1.8.0",
            "pkg:deb/debian/curl@7.88?os=linux&arch=amd64",
            "pkg:generic/Weird_Name@1.0#a/b",
            "pkg:cargo/serde@1.0.197",
            "pkg:pypi/typing_extensions@4.0",
            // Found by `cargo fuzz run purl`, minimized to 10 bytes. The subpath
            // normalized to a single space, Display wrote it unencoded, and
            // parse() trims — so the canonical form reparsed to a PURL with no
            // subpath at all.
            "pkg:f/k# /",
            "pkg:npm/a@1# ",
            "pkg:npm/a@1#a b/c d",
            // Qualifier keys outside the permitted charset must not survive into
            // a canonical form that cannot reproduce them.
            "pkg:npm/a@1?ke y=v&ok=v2",
            // Second fuzz find: a namespace segment decoding to contain `/`.
            "pkg:F/:%%2F/F",
            "pkg:npm/a%2Fb/c@1",
            "pkg:golang/a//b/c@1",
            // Third fuzz find: a subpath decoding to a bare separator.
            "pkg:F/F#%2F",
            "pkg:npm/a@1#%2F",
            "pkg:npm/a@1#a%2Fb/c",
            // Fourth fuzz find: a namespace that survives one decode but not
            // two, which is how the double-decode was caught.
            "pkg:F/%%%3333/Ff",
            "pkg:npm/%25%2533/a@1",
            "pkg:generic/100%/a@1",
        ];
        for case in cases {
            let once = p(case);
            let twice = p(&once.to_string());
            assert_eq!(once, twice, "not idempotent: {case}");
            assert_eq!(
                once.to_string(),
                twice.to_string(),
                "unstable string: {case}"
            );
        }
    }

    #[test]
    fn serde_round_trip() {
        let purl = p("pkg:npm/%40angular/core@17.0.0");
        let json = serde_json::to_string(&purl).unwrap_or_default();
        assert_eq!(json, "\"pkg:npm/%40angular/core@17.0.0\"");
        let back: Purl = serde_json::from_str(&json).unwrap_or_else(|_| p("pkg:generic/x"));
        assert_eq!(purl, back);
    }

    // Stage 0 exit criterion: zero panics across the corpus. Malformed input
    // produces errors, never crashes.
    #[test]
    fn hostile_input_never_panics() {
        let inputs = [
            "",
            "pkg:",
            "pkg:/",
            "pkg://",
            "pkg:@",
            "pkg:npm/@",
            "pkg:npm/foo@",
            "pkg:npm/foo?",
            "pkg:npm/foo#",
            "pkg:npm/foo?&&&",
            "pkg:npm/foo?=v",
            "pkg:npm/foo@@@1",
            "pkg:npm/%",
            "pkg:npm/%zz",
            "pkg:npm/foo#../../etc/passwd",
            "pkg:\u{0}/foo",
            "pkg:npm/\u{202e}evil",
            &"pkg:npm/".repeat(500),
        ];
        for input in inputs {
            let _ = Purl::parse(input);
        }
    }
}
