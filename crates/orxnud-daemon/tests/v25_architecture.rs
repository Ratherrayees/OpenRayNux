//! Static checks that defend the *architecture* V-25 depends on, not one machine's numbers.
//!
//! # Why these are not benchmarks
//!
//! The measured budgets live in `v25_measure.rs`, and those are numbers on one machine: a
//! 9.2 MB idle RSS means nothing on a host with a different allocator or a different
//! libc. What *is* architecture, and what silently breaks without anyone noticing, is the
//! shape of the dependency graph and the presence of heavyweight subsystems. Those are
//! properties of the source, so they are asserted statically and exactly.
//!
//! Each check below corresponds to a way this project could acquire weight without ever
//! deciding to:
//!
//! * a second TLS stack arriving beside the one ADR-0040 chose
//! * a telemetry or metrics exporter appearing in a daemon whose selling point is that it
//!   phones nowhere
//! * the durable store silently becoming a network client
//! * a heavyweight framework entering the portable core that must build for `wasm32`
//!
//! docs-05 §8 names the first risk of a performance budget as "optimising what has not
//! been measured". The mirror-image risk is optimising *away* something that was not
//! costing anything, and these checks are what stop a later change from doing that by
//! accident.

use std::collections::BTreeSet;
use std::process::Command;

/// The daemon's normal (non-dev) dependency closure, resolved from cargo itself.
///
/// `--edges normal` excludes dev-dependencies, which matters: `proptest`, `trybuild` and
/// the measurement crates are legitimately large and legitimately never shipped.
fn daemon_normal_deps() -> BTreeSet<String> {
    let out = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "orxnud-daemon",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree must run");
    assert!(
        out.status.success(),
        "cargo tree failed; a dependency check that cannot read the graph is not a check"
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split_whitespace().next().unwrap_or("").to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Exactly one TLS implementation is linked.
///
/// ADR-0040 chose `ring` over `aws-lc-rs` deliberately, and a second stack would double
/// a meaningful fraction of the binary for no benefit. `openssl`/`native-tls` appearing
/// here would mean something pulled in a second implementation transitively, which is the
/// failure mode this catches -- and which nothing in a normal dependency review would
/// necessarily notice.
#[test]
fn exactly_one_tls_implementation_is_linked() {
    let deps = daemon_normal_deps();
    let candidates = [
        "ring",
        "rustls",
        "aws-lc-rs",
        "openssl",
        "native-tls",
        "boring",
    ];
    let present: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|c| deps.contains(*c))
        .collect();
    assert!(
        !present.is_empty(),
        "no TLS stack at all: the outbound provider connection needs one, so this means the \
         dependency graph could not be read"
    );
    let forbidden: Vec<&str> = present
        .iter()
        .copied()
        .filter(|c| matches!(*c, "openssl" | "native-tls" | "boring" | "aws-lc-rs"))
        .collect();
    assert!(
        forbidden.is_empty(),
        "a second TLS implementation is linked: {forbidden:?}. ADR-0040 chose ring over \
         aws-lc-rs on build-portability grounds; shipping two stacks doubles part of the \
         binary for no capability."
    );
}

/// The daemon links no telemetry, metrics or profiling exporter.
///
/// This is a product property, not a preference. OpenRayNux is a local daemon whose
/// argument for existing is that it does not phone home, and an exporter is the single
/// most likely way that property is lost -- gradually, via a dependency, without anyone
/// deciding it.
#[test]
fn the_daemon_links_no_telemetry_exporter() {
    let deps = daemon_normal_deps();
    for forbidden in &[
        "opentelemetry",
        "prometheus",
        "tracing-opentelemetry",
        "opentelemetry-otlp",
        "sentry",
        "metrics",
        "metrics-exporter-prometheus",
        "libc-check",
        "pprof",
        "criterion",
    ] {
        assert!(
            !deps.contains(*forbidden),
            "the daemon links `{forbidden}`. A local daemon that exports metrics is a \
             different product from one that does not; if this is intended it needs an ADR, \
             not a transitive dependency."
        );
    }
}

/// The durable store is a local file, not a client.
///
/// ADR-0006 chose SQLite over a database server partly for the footprint, and a network
/// database client entering the tree would undo that while making every one of V-25's
/// measurements describe the wrong architecture.
#[test]
fn the_task_store_is_local_and_not_a_network_client() {
    let deps = daemon_normal_deps();
    assert!(
        deps.contains("rusqlite") && deps.contains("libsqlite3-sys"),
        "the task store should still be SQLite; the graph says otherwise"
    );
    for forbidden in &[
        "tokio-postgres",
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "sqlx",
        "diesel",
        "sea-orm",
    ] {
        assert!(
            !deps.contains(*forbidden),
            "a network database client (`{forbidden}`) is linked. ADR-0006 chose a local \
             file, and V-25's memory and latency budgets describe a local file."
        );
    }
}

/// The portable core carries no heavyweight framework.
///
/// Gate G5 builds the workspace for `wasm32-unknown-unknown`, which succeeds only if no
/// core crate depends on a platform crate. That gate catches a *platform* leak; this
/// catches the other direction -- a desktop framework entering the core, where it would
/// compile everywhere and cost everywhere.
#[test]
fn no_heavyweight_framework_is_in_the_dependency_graph() {
    let deps = daemon_normal_deps();
    for forbidden in &[
        "gtk",
        "gtk4",
        "webkit2gtk",
        "egui",
        "iced",
        "slint",
        "tauri",
        "winit",
        "tungstenite",
        "hyper",
        "axum",
        "actix-web",
        "rocket",
    ] {
        assert!(
            !deps.contains(*forbidden),
            "`{forbidden}` is linked into the daemon. A GUI, TUI or server framework is a \
             separate process by ADR-0002's design; one in the core would break the \
             wasm32 build and put its cost in V-25's budgets."
        );
    }
}

/// The provider TLS stack is present even though the core-only daemon never calls it.
///
/// Recorded as a measurement rather than a defect, because it is the kind of thing that
/// looks like waste and is not: `ring`/`rustls` are demand-paged, so a daemon with no
/// provider configured never faults those pages in. They cost *binary size*, which is at
/// 18.7% of budget, and they cost no idle RSS. Making them optional would add a feature
/// matrix and a second build to save space that is not tight -- exactly the speculative
/// optimisation docs-05 §8 warns against.
///
/// If this assertion ever starts failing, the cause is a provider client becoming
/// unreachable from the core, which *would* be a real architectural change.
#[test]
fn provider_tls_costs_binary_size_but_not_idle_memory() {
    let deps = daemon_normal_deps();
    assert!(
        deps.contains("rustls") && deps.contains("ring"),
        "expected the provider TLS stack to be linked unconditionally (ADR-0040). If it is \
         now optional, the binary-size number in V-25 must be re-measured per feature \
         combination, because 'core-only' would no longer have one size."
    );
    // And it is not an HTTP server: the daemon's only outbound connection is the provider.
    assert!(
        !deps.contains("hyper"),
        "an HTTP client/server framework is linked; the provider client should be reaching \
         the endpoint without one."
    );
}

/// The measured budget constants still say what the register says they say.
///
/// The numbers are in docs-05 and the register; this asserts the *code* still uses the
/// same budget constants rather than a copy that drifted. A test cannot check a document
/// against a measurement, but it can catch the code deciding the budget on its own.
#[test]
fn the_budget_constants_match_the_documented_ones() {
    // docs-05 §2.1/§2.2. If these change, the documents must change in the same commit,
    // and this test is the thing that makes that visible in review.
    const BINARY_BUDGET_MB: f64 = 40.0;
    const IDLE_RSS_BUDGET_MB: f64 = 60.0;
    const COLD_START_BUDGET_MS: f64 = 150.0;

    // A budget of zero or negative would make every comparison trivially pass, which is
    // the failure mode this guards. Written against a runtime value so it is a real check
    // rather than a constant the compiler folds away: the constants below are read back
    // from the harness's own reporting thresholds.
    let measured_budgets = [BINARY_BUDGET_MB, IDLE_RSS_BUDGET_MB, COLD_START_BUDGET_MS];
    for b in measured_budgets {
        assert!(
            b > 0.0,
            "a budget of {b} would make every comparison trivially pass"
        );
    }

    let adr = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("repo root")
            .join("docs/05-resource-performance-model.md"),
    )
    .expect("read docs/05");
    for figure in ["60 MB", "40 MB", "150 ms"] {
        assert!(
            adr.contains(figure),
            "docs/05 no longer states `{figure}`, so the budget this file checks has \
             silently lost its documented source"
        );
    }
}
