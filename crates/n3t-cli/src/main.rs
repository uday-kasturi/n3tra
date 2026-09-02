//! `n3t` — the unprivileged, user-facing binary.
//!
//! INV-1: this binary runs as the ordinary build user with zero elevated
//! privilege. It never attaches probes; that is `n3t-observe`'s job, and the two
//! never share a process.
//!
//! INV-4: nothing here writes to a user repository. Stage 0 is read-only by
//! construction — the only writes are to the advisory cache under `~/.cache`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use n3t_advisory::{AuditOptions, AuditTarget, OsvClient, RegistryClient};
use n3t_core::confidence::Confidence;
use n3t_core::verdict::{Coverage, Verdict};

mod report;

use report::{Format, Mode};

#[derive(Parser)]
#[command(
    name = "n3t",
    version,
    about = "Build-time dependency observability and remediation",
    long_about = "n3tra — Stage 0: multi-ecosystem inventory and advisory audit.\n\n\
                  Observation layers L1-L3 arrive in Stages 1-2. Until then every\n\
                  result is derived from what the build DECLARES (L0), not from\n\
                  what it was observed to do."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inventory declared dependencies. No network access.
    Scan(ScanArgs),
    /// Inventory, then match against advisories.
    Audit(AuditArgs),
    /// Show where the advisory cache lives and how much is in it.
    Cache,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Skip native tooling; parse lockfiles only.
    #[arg(long)]
    no_native: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "human")]
    format: Format,
}

#[derive(clap::Args)]
struct AuditArgs {
    /// Directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Skip native tooling; parse lockfiles only.
    #[arg(long)]
    no_native: bool,
    /// Only report vulnerabilities at or above this CVSS base score.
    ///
    /// Never filters malicious-package (MAL-) advisories.
    #[arg(long, value_name = "SCORE")]
    cvss: Option<f64>,
    /// Flag dependencies published within this many days.
    #[arg(long, value_name = "DAYS")]
    min_version_age: Option<i64>,
    /// Use only cached advisory data. A cache miss yields `unknown`, not `clean`.
    #[arg(long)]
    offline: bool,
    /// Attribution confidence required for a finding to gate the build.
    #[arg(long, value_enum, default_value = "high")]
    gate_floor: GateFloor,
    /// Output format.
    #[arg(long, value_enum, default_value = "human")]
    format: Format,
    /// Advisory cache directory.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum GateFloor {
    /// Gate on medium-confidence findings and above.
    Medium,
    /// Gate only on exact ownership records. The default.
    High,
}

impl From<GateFloor> for Confidence {
    fn from(g: GateFloor) -> Self {
        match g {
            GateFloor::Medium => Confidence::Medium,
            GateFloor::High => Confidence::High,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => cmd_scan(args),
        Command::Audit(args) => cmd_audit(args),
        Command::Cache => cmd_cache(),
    }
}

fn cmd_scan(args: ScanArgs) -> ExitCode {
    let inventory = n3t_parse::scan(&args.path, !args.no_native);

    // Even a pure inventory can be incomplete, and an incomplete inventory must
    // not read as a clean one (INV-5).
    let coverage = Coverage::partial(inventory.gaps.clone());
    let verdict = Verdict::new(coverage, vec![]);

    let text = match args.format {
        Format::Human => report::human(&inventory, &[], &verdict, 0, Mode::Inventory),
        Format::Json => report::json(&inventory, &[], &verdict, 0, Mode::Inventory),
        Format::Sarif => report::sarif(&[], &verdict),
        Format::Junit => report::junit(&[], &verdict),
    };
    println!("{text}");

    if args.format == Format::Human {
        println!("Discovered packages:");
        for pkg in &inventory.packages {
            let marker = if pkg.direct { "direct" } else { "transitive" };
            println!("  {:<12} {}", marker, pkg.purl);
        }
    }

    exit_code(&verdict)
}

fn cmd_audit(args: AuditArgs) -> ExitCode {
    let inventory = n3t_parse::scan(&args.path, !args.no_native);

    let cache_dir = args.cache_dir.unwrap_or_else(OsvClient::default_cache_dir);
    let client = OsvClient::new(cache_dir, args.offline);
    let registry = RegistryClient::new(args.offline);

    let options = AuditOptions {
        min_cvss: args.cvss,
        min_version_age_days: args.min_version_age,
        offline: args.offline,
    };

    // A package with no resolved version cannot be matched against an advisory.
    // Rather than dropping it (which would shrink the denominator and make the
    // scan look more complete than it is), it becomes an explicit gap.
    let mut gaps = inventory.gaps.clone();
    let mut targets = Vec::new();
    for pkg in &inventory.packages {
        if pkg.purl.version().is_none() {
            gaps.push(n3t_core::verdict::UnknownReason::InventoryUnavailable {
                ecosystem: pkg.purl.ty().to_string(),
                detail: format!(
                    "{} has no resolved version; cannot match advisories",
                    pkg.purl
                ),
            });
            continue;
        }
        targets.push(AuditTarget {
            purl: pkg.purl.clone(),
            confidence: pkg.confidence,
        });
    }

    let result = n3t_advisory::audit(
        &targets,
        &client,
        &registry,
        &options,
        n3t_advisory::now_unix(),
    );
    gaps.extend(result.gaps);

    let verdict = Verdict::new(
        Coverage::partial(gaps),
        result.findings.iter().map(|f| f.summary(false)).collect(),
    )
    .with_gate_floor(args.gate_floor.into());

    let text = match args.format {
        Format::Human => report::human(
            &inventory,
            &result.findings,
            &verdict,
            result.checked,
            Mode::Audit,
        ),
        Format::Json => report::json(
            &inventory,
            &result.findings,
            &verdict,
            result.checked,
            Mode::Audit,
        ),
        Format::Sarif => report::sarif(&result.findings, &verdict),
        Format::Junit => report::junit(&result.findings, &verdict),
    };
    println!("{text}");

    exit_code(&verdict)
}

fn cmd_cache() -> ExitCode {
    let client = OsvClient::new(OsvClient::default_cache_dir(), true);
    println!("advisory cache: {}", client.cache_dir().display());
    println!("cached entries: {}", client.cache_size());
    ExitCode::SUCCESS
}

/// 0 = clean, 1 = failed, 2 = unknown.
///
/// `unknown` is deliberately its own code so CI can be configured to treat it as
/// either a pass or a failure — a choice the operator should make explicitly
/// rather than inherit.
fn exit_code(verdict: &Verdict) -> ExitCode {
    ExitCode::from(verdict.exit_code().clamp(0, 255) as u8)
}
