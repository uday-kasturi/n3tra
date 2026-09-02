//! Every core type must survive a JSON round trip.
//!
//! This exists because serde's *internally* tagged enum representation cannot
//! encode a newtype variant whose content serializes as a scalar — it fails at
//! runtime, not at compile time, and the failure surfaces as an error value that
//! is easy to swallow. Every enum added to `n3t-core` gets a case here.
//!
//! These types cross a trust boundary (the observer writes an event log that the
//! unprivileged fixer reads — INV-1), so an encoding that only fails in
//! production is a real availability bug, not a cosmetic one.

// Integration tests are a separate crate, so the `cfg_attr(test, ...)` allow in
// lib.rs does not reach here. Panicking is the correct behavior in a test.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use n3t_core::confidence::Confidence;
use n3t_core::fixplan::{
    Fix, FixPlan, PatchApplication, PatchProvenance, Rung, Ttl, Verification, VerifyTier,
};
use n3t_core::graph::{EdgeKind, Graph, Layer, NodeKind};
use n3t_core::purl::Purl;
use n3t_core::verdict::{
    Coverage, DetachedBuilder, FindingSummary, Severity, UnknownReason, Verdict,
};

const NOW: i64 = 1_760_000_000;

fn round_trip<T>(value: &T, label: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json =
        serde_json::to_string(value).unwrap_or_else(|e| panic!("{label}: serialize failed: {e}"));
    let back: T = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("{label}: deserialize failed: {e}\njson: {json}"));
    assert_eq!(value, &back, "{label}: round trip changed the value");
}

fn purl(s: &str) -> Purl {
    Purl::parse(s).unwrap_or_else(|e| panic!("bad test purl {s}: {e}"))
}

fn ttl() -> Ttl {
    Ttl::days_from(NOW, 30).unwrap_or_else(|e| panic!("bad test ttl: {e}"))
}

#[test]
fn purls_round_trip() {
    for s in [
        "pkg:npm/%40angular/core@17.0.0",
        "pkg:deb/debian/openssl@1:3.0.11-1~deb12u2",
        "pkg:pypi/torch@2.1.0+cu118",
        "pkg:golang/github.com/gorilla/mux@1.8.0",
        "pkg:deb/debian/curl@7.88?arch=amd64&os=linux",
    ] {
        round_trip(&purl(s), s);
    }
}

#[test]
fn node_kinds_round_trip() {
    round_trip(&NodeKind::Package(purl("pkg:npm/a@1")), "NodeKind::Package");
    round_trip(
        &NodeKind::File {
            path: "/usr/lib/libssl.so".into(),
            sha256: Some("ab".repeat(32)),
        },
        "NodeKind::File",
    );
    round_trip(
        &NodeKind::Process {
            pid: 42,
            exe: "/usr/bin/npm".into(),
        },
        "NodeKind::Process",
    );
    round_trip(
        &NodeKind::Endpoint {
            host: "registry.npmjs.org".into(),
            port: 443,
        },
        "NodeKind::Endpoint",
    );
}

#[test]
fn every_unknown_reason_round_trips() {
    let reasons = [
        UnknownReason::ObserverTerminated {
            at_build_step: Some("RUN npm ci".into()),
        },
        UnknownReason::ProbeLoadFailed {
            detail: "no BTF".into(),
        },
        UnknownReason::EventLossPossible {
            dropped: Some(1024),
        },
        UnknownReason::ShimBypassed {
            invocation: "/usr/bin/npm install".into(),
        },
        UnknownReason::InventoryUnavailable {
            ecosystem: "npm".into(),
            detail: "lockfileVersion 4 unknown".into(),
        },
    ];
    for reason in &reasons {
        round_trip(reason, "UnknownReason");
    }

    // INV-11: every detached-builder variant, since these are the silent ones.
    for builder in [
        DetachedBuilder::RemoteDockerHost,
        DetachedBuilder::BuildxRemoteDriver,
        DetachedBuilder::MicroVmGuestKernel,
        DetachedBuilder::GvisorSandbox,
        DetachedBuilder::TargetCgroupNeverObserved,
    ] {
        round_trip(
            &UnknownReason::BuildRanElsewhere { builder },
            "BuildRanElsewhere",
        );
    }
}

#[test]
fn verdicts_round_trip_and_preserve_outcome() {
    let partial = Verdict::new(
        Coverage::partial(vec![UnknownReason::BuildRanElsewhere {
            builder: DetachedBuilder::RemoteDockerHost,
        }]),
        vec![FindingSummary {
            id: "GHSA-xxxx".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            pre_existing: false,
        }],
    );
    round_trip(&partial, "Verdict(partial)");

    // INV-5 must survive the trust boundary: a verdict that was Unknown before
    // serialization must not deserialize into something that passes.
    let json = serde_json::to_string(&partial).unwrap_or_else(|e| panic!("{e}"));
    let back: Verdict = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back.outcome(), partial.outcome());
    assert_eq!(back.exit_code(), 2);
}

#[test]
fn every_rung_round_trips() {
    let rungs = [
        Rung::Upgrade {
            from: "1.0.0".into(),
            to: "1.0.1".into(),
        },
        Rung::TransitiveOverride {
            via: purl("pkg:npm/parent@2"),
            to: "3.0.0".into(),
            mechanism: "overrides".into(),
        },
        Rung::BackportPatch {
            provenance: PatchProvenance::UpstreamCommit {
                repo: "https://github.com/example/lib".into(),
                commit: "a".repeat(40),
            },
            application: PatchApplication::Clean,
            expires: ttl(),
        },
        Rung::BackportPatch {
            provenance: PatchProvenance::DistroBackport {
                distro: "debian".into(),
                patch_id: "CVE-2026-1234.patch".into(),
            },
            application: PatchApplication::Clean,
            expires: ttl(),
        },
        Rung::VirtualPatch {
            target_symbol: "lib.parse".into(),
            expires: ttl(),
        },
        Rung::StripBuildArtifact {
            path: "/usr/bin/gcc".into(),
            expires: ttl(),
        },
        Rung::Contain {
            policy: "deny egress".into(),
            expires: ttl(),
        },
    ];
    for rung in &rungs {
        round_trip(rung, &format!("Rung {}", rung.number()));
    }
}

// INV-6 across the trust boundary: a TTL must survive serialization intact.
// A mitigation whose expiry got lost in transit is a permanent mitigation.
#[test]
fn ttl_survives_serialization() {
    let plan = FixPlan::new(
        "main",
        vec![Fix {
            finding_id: "f1".into(),
            package: purl("pkg:npm/a@1"),
            rung: Rung::VirtualPatch {
                target_symbol: "x".into(),
                expires: ttl(),
            },
            verification: Verification::Verified {
                tier: VerifyTier::FullObserved,
            },
            needs_review: false,
        }],
    );
    round_trip(&plan, "FixPlan");

    let json = serde_json::to_string(&plan).unwrap_or_else(|e| panic!("{e}"));
    let back: FixPlan = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
    let fix = back.fixes.first().unwrap_or_else(|| panic!("fix vanished"));
    let expires = fix
        .rung
        .ttl()
        .unwrap_or_else(|| panic!("TTL vanished in transit"));
    assert_eq!(expires.granted_days(), 30);
    assert!(expires.is_expired(NOW + 31 * 86_400));
}

#[test]
fn verification_states_round_trip() {
    round_trip(
        &Verification::Verified {
            tier: VerifyTier::ResolverDryRun,
        },
        "Verified",
    );
    round_trip(
        &Verification::Unverified {
            reason: "verify budget exhausted".into(),
        },
        "Unverified",
    );
}

#[test]
fn populated_graph_round_trips() {
    let mut g = Graph::new();
    let proc = g.observe(
        NodeKind::Process {
            pid: 7,
            exe: "/usr/bin/npm".into(),
        },
        Layer::L2Kernel,
        Confidence::High,
    );
    let pkg = g.observe(
        NodeKind::Package(purl("pkg:npm/a@1")),
        Layer::L0Declared,
        Confidence::High,
    );
    let ep = g.observe(
        NodeKind::Endpoint {
            host: "registry.npmjs.org".into(),
            port: 443,
        },
        Layer::L2Kernel,
        Confidence::Medium,
    );
    g.relate(proc, pkg, EdgeKind::Loaded, Layer::L2Kernel);
    g.relate(pkg, ep, EdgeKind::FetchedFrom, Layer::L1Interposed);

    let json = serde_json::to_string(&g).unwrap_or_else(|e| panic!("graph serialize: {e}"));
    let mut back: Graph =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("graph deserialize: {e}"));
    back.reindex();
    assert_eq!(g, back);
    assert_eq!(back.edges().len(), 2);
}
