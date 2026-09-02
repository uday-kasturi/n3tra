//! n3tra core types: PURL identity, the artifact dependency graph, verdicts, and
//! the fixplan schema. Pure data and logic — this crate performs no I/O, has no
//! network access, and cannot touch a filesystem.
//!
//! Several project invariants are enforced structurally here rather than by
//! convention, because they are the ones whose violation is silent:
//!
//! - **INV-5** — [`verdict::Outcome::Clean`] is derived, never constructed, and
//!   only from `Coverage::Complete`. Absent evidence cannot become a pass.
//! - **INV-6** — [`fixplan::Ttl`] is mandatory on rungs 3–6, finite by
//!   construction, with no `Permanent` variant to reach for.
//! - **INV-8** — [`confidence::Confidence`] carries its consequences as methods,
//!   so `Low` cannot gate or generate a fixplan under any configuration.
//! - **INV-9** — [`wording`] checks report text mechanically.
//! - **INV-13** — [`graph::Layer::can_prevent`] is true only for L1.
//!
//! **INV-4**: nothing in this crate writes to a user repository. A `FixPlan` is a
//! value; applying one is a separate step the user invokes.

#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

pub mod confidence;
pub mod fixplan;
pub mod graph;
mod pct;
pub mod purl;
pub mod verdict;
pub mod wording;

pub use confidence::Confidence;
pub use fixplan::{FixPlan, Rung, Ttl};
pub use graph::{Graph, Layer, NodeKind};
pub use purl::{Purl, PurlError};
pub use verdict::{Coverage, Outcome, Severity, UnknownReason, Verdict};
