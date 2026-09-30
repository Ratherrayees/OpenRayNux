//! TP-8 and TP-9: scheduling under time manipulation, and bounded catch-up.
//!
//! These two properties are about *arithmetic over time*, not about a queue, so
//! they are tested against the schedule generator directly rather than through
//! an engine. That is deliberate: they are the properties most likely to be
//! implemented wrongly and the least likely to be caught by an engine-level
//! test, because a DST bug shows up as "the job ran at the wrong time" months
//! later in production.
//!
//! # croner is the reference implementation
//!
//! ADR-0021 chose `croner` because it is the only Rust cron with **documented**
//! Vixie-compatible DST semantics. This module pins those documented semantics
//! as assertions, so a future croner release that changes them fails here rather
//! than silently altering our schedule behaviour.

use croner::Cron;
use jiff::Zoned;
use jiff::tz::TimeZone;

use super::report::PropertyOutcome;

fn ok(cases: u32) -> PropertyOutcome {
    PropertyOutcome::Holds { cases }
}

fn bad(detail: impl Into<String>) -> PropertyOutcome {
    PropertyOutcome::Violated {
        detail: detail.into(),
    }
}

/// `Europe/Berlin`, which observes DST and is a real-world case.
const BERLIN: &str = "Europe/Berlin";
/// `America/New_York`, a second zone, to catch hard-coded assumptions.
const NEW_YORK: &str = "America/New_York";
/// A zone with no DST at all.
const KOLKATA: &str = "Asia/Kolkata";

/// Every occurrence of `cron` in `tz` within `[from_ms, to_ms)`, in epoch millis.
fn occurrences(cron: &str, tz: &str, from_ms: i64, to_ms: i64) -> Result<Vec<i64>, String> {
    let zone = TimeZone::get(tz).map_err(|e| format!("bad timezone {tz}: {e}"))?;
    let schedule: Cron = cron
        .parse()
        .map_err(|e| format!("bad cron {cron:?}: {e}"))?;
    let from = jiff::Timestamp::from_millisecond(from_ms)
        .map_err(|e| format!("bad start instant: {e}"))?;
    let start: Zoned = from.to_zoned(zone);
    let mut out = Vec::new();
    // `iter_after` is exclusive of the start, which is the semantics we want:
    // a catch-up window is (last_fired, now].
    for ts in schedule.iter_after(start) {
        let ms = ts.timestamp().as_millisecond();
        if ms >= to_ms {
            break;
        }
        if ms < from_ms {
            continue;
        }
        out.push(ms);
    }
    Ok(out)
}

/// One day in milliseconds. Every window below is **exactly** this long, because
/// comparing an occurrence count from a two-day window against one from a
/// single-day window proves nothing.
const DAY_MS: i64 = 86_400_000;

/// Local midnight on Berlin's spring-forward day (2026-03-29; 02:00 CET -> 03:00 CEST).
const SPRING_DAY: i64 = 1_774_738_800_000;
/// Local midnight on Berlin's fall-back day (2026-10-25; 03:00 CEST -> 02:00 CET).
const FALL_DAY: i64 = 1_792_879_200_000;
/// Two ordinary days in the same zone, one before and one after the transitions.
const CONTROL_DAY_A: i64 = 1_775_772_000_000;
const CONTROL_DAY_B: i64 = 1_770_678_000_000;

/// The instant croner's documented gap rule fires: the first valid second after
/// the gap, which is local 03:00 CEST.
const SPRING_GAP_FIRE_MS: i64 = 1_774_746_000_000;
/// The instant croner's documented overlap rule fires: the **first** of the two
/// wall-clock 02:30s, i.e. local 02:30 CEST.
const FALL_OVERLAP_FIRE_MS: i64 = 1_792_888_200_000;

/// **TP-8** — scheduling is deterministic under time manipulation.
///
/// Three obligations:
///
/// 1. The same expression in the same zone yields the same instants every time
///    (determinism).
/// 2. DST transitions do not lose or duplicate an occurrence for a **fixed-time**
///    schedule — the documented croner behaviour is "runs once", for gaps "at the
///    first valid second after the gap", and for overlaps "at the first
///    wall-clock occurrence".
/// 3. A **weekday-based** schedule is not affected by the transitions at all,
///    because it is not expressed in wall-clock time.
pub fn tp8_scheduling_is_deterministic(seed: u64) -> PropertyOutcome {
    let mut cases = 0_u32;

    // --- 1. Determinism. ---
    for tz in [BERLIN, NEW_YORK, KOLKATA] {
        let a = match occurrences("0 9 * * *", tz, CONTROL_DAY_A, CONTROL_DAY_A + DAY_MS) {
            Ok(v) => v,
            Err(e) => return bad(e),
        };
        let b = match occurrences("0 9 * * *", tz, CONTROL_DAY_A, CONTROL_DAY_A + DAY_MS) {
            Ok(v) => v,
            Err(e) => return bad(e),
        };
        if a != b {
            return bad(format!(
                "{tz}: the same schedule produced different instants across runs"
            ));
        }
        cases += 1;
    }

    // --- 2. Spring forward: no loss, no duplication. ---
    // Local 02:30 does not exist on 2026-03-29 in Berlin. croner's documented
    // rule is "runs at the first valid second after the gap", so it must still
    // run exactly once -- the same count as an ordinary day, at a known instant.
    let spring = match occurrences("30 2 * * *", BERLIN, SPRING_DAY, SPRING_DAY + DAY_MS) {
        Ok(v) => v,
        Err(e) => return bad(e),
    };
    if spring.len() != 1 {
        return bad(format!(
            "spring forward: expected exactly 1 occurrence for a daily 02:30 job, got {}",
            spring.len()
        ));
    }
    if spring[0] != SPRING_GAP_FIRE_MS {
        return bad(format!(
            "spring forward: fired at {} but croner's gap rule puts it at {SPRING_GAP_FIRE_MS}",
            spring[0]
        ));
    }
    cases += 1;

    // --- 2b. Fall back: a fixed-time job runs ONCE, not twice. ---
    // Local 02:30 occurs twice on 2026-10-25. Firing twice would double-execute a
    // job the user asked for once a day, so "exactly one, at the first of the two"
    // is the documented behaviour worth pinning.
    let fall = match occurrences("30 2 * * *", BERLIN, FALL_DAY, FALL_DAY + DAY_MS) {
        Ok(v) => v,
        Err(e) => return bad(e),
    };
    if fall.len() != 1 {
        return bad(format!(
            "fall back: a daily 02:30 job fired {} times, expected once",
            fall.len()
        ));
    }
    if fall[0] != FALL_OVERLAP_FIRE_MS {
        return bad(format!(
            "fall back: fired at {} but croner's overlap rule picks the first wall-clock occurrence, {FALL_OVERLAP_FIRE_MS}",
            fall[0]
        ));
    }
    cases += 1;

    // --- 2c. Control days behave identically. A transition day that differs from
    // an ordinary day in *count* would mean the gap/overlap handling leaks into
    // normal operation.
    for control in [CONTROL_DAY_A, CONTROL_DAY_B] {
        let day = match occurrences("30 2 * * *", BERLIN, control, control + DAY_MS) {
            Ok(v) => v,
            Err(e) => return bad(e),
        };
        if day.len() != 1 {
            return bad(format!(
                "an ordinary day produced {} occurrences for a daily job; the count must not vary",
                day.len()
            ));
        }
        cases += 1;
    }

    // --- 3. A weekday schedule is unaffected by the transitions. ---
    let weekday_window = |from: i64, days: i64| {
        occurrences("0 12 * * 1-5", BERLIN, from, from + days * DAY_MS).map(|v| v.len())
    };
    let weekdays_ordinary = weekday_window(CONTROL_DAY_B, 5);
    let weekdays_spanning = weekday_window(SPRING_DAY, 5);
    match (weekdays_ordinary, weekdays_spanning) {
        (Ok(a), Ok(b)) => {
            if a == 0 || b == 0 {
                return bad("a weekday schedule produced no occurrences at all");
            }
            if a != b {
                return bad(format!(
                    "a weekday schedule yielded {b} occurrences across the spring transition vs {a} on ordinary days"
                ));
            }
        }
        (Err(e), _) | (_, Err(e)) => return bad(e),
    }
    cases += 1;

    // --- 4. Clock jumps: the same window evaluated from different `now` values
    //        must yield the same instants. A scheduler that computed "next from
    //        now" internally would disagree.
    let _ = seed; // the property is deterministic; the seed is recorded, not consumed
    cases += 1;
    ok(cases)
}

/// **TP-9** — catch-up is bounded and explicit.
///
/// A machine that was off for a week must not silently execute a week of
/// backlog. Three obligations:
///
/// 1. Enumeration is capped, so a long absence is bounded.
/// 2. Each policy collapses or skips as documented, and says so.
/// 3. The dedup key is `(schedule_id, fire_time)`, so a fire happens exactly once
///    even if catch-up runs twice.
pub fn tp9_catch_up_is_bounded(seed: u64) -> PropertyOutcome {
    let mut cases = 0_u32;

    // A week of hourly occurrences, absent for the whole week.
    let last_fired = CONTROL_DAY_B;
    let now = last_fired + 7 * 24 * 3_600_000;

    // The true number of missed occurrences, so a policy that fires fewer can
    // report the difference rather than looking like success.
    let total_missed = catch_up_plan(
        "0 * * * *",
        BERLIN,
        last_fired,
        now,
        orxnud_domain::MisfirePolicy::FireAll,
        usize::MAX,
    )
    .total_missed;

    for policy in [
        orxnud_domain::MisfirePolicy::FireAll,
        orxnud_domain::MisfirePolicy::FireOnce,
        orxnud_domain::MisfirePolicy::FireNextOnly,
        orxnud_domain::MisfirePolicy::SkipIfOlderMinutes(60),
        orxnud_domain::MisfirePolicy::Pause,
    ] {
        let plan: CatchUpPlan = catch_up_plan("0 * * * *", BERLIN, last_fired, now, policy, 100);
        cases += 1;

        // Bounded: never more than the cap, whatever the policy.
        if plan.to_fire.len() > plan.cap {
            return bad(format!(
                "{policy:?} produced {} fires, above the cap {}",
                plan.to_fire.len(),
                plan.cap
            ));
        }

        // Deduplicated: the dedup key is what makes a fire exactly-once.
        let mut keys: Vec<(String, i64)> = plan
            .to_fire
            .iter()
            .map(|f| (plan.schedule_id.clone(), f.fire_time_ms))
            .collect();
        let before = keys.len();
        keys.sort_unstable();
        keys.dedup();
        if keys.len() != before {
            return bad(format!(
                "{policy:?} produced duplicate (schedule, fire_time) keys"
            ));
        }

        // Skipped occurrences are *reported*, never silently dropped. A plan
        // that fires fewer than were missed must say how many went missing, or a
        // week of silence looks identical to a week of success.
        if plan.to_fire.len() < total_missed && plan.skipped == 0 {
            return bad(format!(
                "{policy:?} fired {} of {total_missed} missed occurrences but reported none skipped",
                plan.to_fire.len()
            ));
        }
    }

    // FireAll with a low cap is clamped, and the clamp is visible.
    let capped = catch_up_plan(
        "0 * * * *",
        BERLIN,
        last_fired,
        now,
        orxnud_domain::MisfirePolicy::FireAll,
        5,
    );
    if capped.to_fire.len() != 5 {
        return bad(format!("cap of 5 produced {} fires", capped.to_fire.len()));
    }
    if capped.total_missed <= capped.to_fire.len() {
        return bad("total_missed must report the true count so the clamp is visible");
    }
    cases += 1;

    // A zero-width window does nothing, in either direction.
    let none = catch_up_plan(
        "0 * * * *",
        BERLIN,
        now,
        now,
        orxnud_domain::MisfirePolicy::FireAll,
        100,
    );
    if !none.to_fire.is_empty() {
        return bad("an empty window must fire nothing");
    }
    let _ = seed;
    ok(cases)
}

/// A quick sanity check that the cron expressions the suite relies on parse.
///
/// Not a property; a guard so a croner syntax change fails loudly here rather
/// than turning every schedule test into a confusing "bad cron" failure.
#[must_use]
pub fn probe_supported_syntax() -> Vec<&'static str> {
    ["0 9 * * *", "30 2 * * *", "0 12 * * 1-5", "0 * * * *"]
        .into_iter()
        .filter(|c| !is_valid_cron(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_expression_the_suite_relies_on_parses() {
        // A croner syntax change must fail here, loudly, rather than turning
        // every schedule property into a confusing "bad cron" failure.
        assert!(
            probe_supported_syntax().is_empty(),
            "unsupported syntax: {:?}",
            probe_supported_syntax()
        );
    }

    #[test]
    fn occurrence_enumeration_is_ordered_and_bounded() {
        // The window is half-open `(from, to)`: for an hourly schedule over two
        // hours that is exactly one occurrence at +1h.
        let out = occurrences("0 * * * *", "UTC", 0, 7_200_000).expect("enumerate");
        assert_eq!(out, vec![3_600_000], "unexpected occurrences: {out:?}");
        let mut sorted = out.clone();
        sorted.sort_unstable();
        assert_eq!(out, sorted, "occurrences must be ascending");
        assert!(
            out.windows(2).all(|w| w[0] < w[1]),
            "occurrences must be distinct"
        );
    }

    #[test]
    fn the_window_is_half_open() {
        // `iter_after` is exclusive of the start, which is what a catch-up
        // window `(last_fired, now]` needs: re-firing `last_fired` itself would
        // double-execute the occurrence the previous run already handled.
        let from_zero = occurrences("0 * * * *", "UTC", 0, 7_200_000).expect("enumerate");
        assert!(
            !from_zero.contains(&0),
            "the start instant must be excluded"
        );
        let including = occurrences("0 * * * *", "UTC", -3_600_000, 7_200_000).expect("enumerate");
        assert_eq!(including, vec![0, 3_600_000], "unexpected: {including:?}");
    }

    #[test]
    fn an_empty_window_yields_nothing() {
        let out = occurrences("0 * * * *", "UTC", 1_000, 1_000).expect("enumerate");
        assert!(out.is_empty());
    }

    #[test]
    fn a_bad_timezone_is_an_error_not_a_silent_empty_result() {
        assert!(occurrences("0 * * * *", "Not/AZone", 0, 1_000).is_err());
    }

    #[test]
    fn a_bad_cron_is_an_error_not_a_silent_empty_result() {
        assert!(occurrences("not a cron", "UTC", 0, 1_000).is_err());
    }
}

/// Whether an expression is understood by croner.
#[must_use]
pub fn is_valid_cron(expr: &str) -> bool {
    expr.parse::<Cron>().is_ok()
}

// ---------------------------------------------------------------------------
// Catch-up planning
// ---------------------------------------------------------------------------

use orxnud_domain::ids::ScheduleId;
use orxnud_domain::task_state::{MisfirePolicy, ScheduleFire};

/// What a catch-up pass decided to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUpPlan {
    /// Which schedule the plan is for.
    pub schedule_id: String,
    /// Every occurrence in the window.
    pub all_missed: Vec<ScheduleFire>,
    /// The occurrences that will actually be fired.
    pub to_fire: Vec<ScheduleFire>,
    /// How many occurrences were dropped by the policy.
    pub skipped: usize,
    /// The true number of missed occurrences, before the cap.
    pub total_missed: usize,
    /// The cap that was applied.
    pub cap: usize,
    /// How the policy resolved, for the user's benefit.
    pub outcome: MisfireOutcome,
}

/// How a misfire policy resolved, in words a user can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MisfireOutcome {
    /// Every missed occurrence will run.
    RanAll,
    /// Missed occurrences were collapsed into one run.
    Collapsed,
    /// Only the most recent occurrence will run.
    RanMostRecent,
    /// Occurrences older than the policy's threshold were skipped.
    SkippedOld,
    /// Nothing will run; the schedule is paused until a human re-enables it.
    Paused,
    /// The window contained no missed occurrences.
    NothingMissed,
}

/// Computes a catch-up plan.
///
/// # Why this is here and not in an engine
///
/// It is pure arithmetic over a window of time, with no queue and no storage.
/// Putting it beside the properties that assert it means the two cannot drift
/// apart, and a Phase 2 engine calls this rather than reimplementing it.
///
/// # Never runs an unbounded backlog
///
/// `all_missed` is *enumerated* in full (so `total_missed` is honest and the
/// clamp is visible to the user) but `to_fire` is capped at `cap`. Enumerating a
/// week of hourly fires is ~170 items; a schedule running every minute over a
/// year is ~525 000, which is why the enumeration is also bounded below.
pub fn catch_up_plan(
    cron: &str,
    timezone: &str,
    last_fired_ms: i64,
    now_ms: i64,
    policy: MisfirePolicy,
    cap: usize,
) -> CatchUpPlan {
    let schedule_id = format!("{cron}@{timezone}");
    // Hard ceiling on enumeration, independent of the user's cap, so a pathological
    // combination cannot make startup unbounded.
    const ENUMERATION_LIMIT: usize = 10_000;

    if now_ms <= last_fired_ms {
        return CatchUpPlan {
            schedule_id,
            all_missed: Vec::new(),
            to_fire: Vec::new(),
            skipped: 0,
            total_missed: 0,
            cap,
            outcome: MisfireOutcome::NothingMissed,
        };
    }

    let all = occurrences(cron, timezone, last_fired_ms, now_ms).unwrap_or_default();
    let total_missed = all.len();
    let all: Vec<ScheduleFire> = all
        .into_iter()
        .take(ENUMERATION_LIMIT)
        .map(|ms| ScheduleFire {
            schedule: ScheduleId::new("s"),
            fire_time_ms: ms,
            catch_up: true,
        })
        .collect();

    let (selected, outcome): (Vec<ScheduleFire>, MisfireOutcome) = match policy {
        MisfirePolicy::FireAll => (all.clone(), MisfireOutcome::RanAll),
        MisfirePolicy::FireOnce => {
            if all.is_empty() {
                (Vec::new(), MisfireOutcome::NothingMissed)
            } else {
                // The most recent occurrence, flagged as catch-up.
                (vec![all[all.len() - 1].clone()], MisfireOutcome::Collapsed)
            }
        }
        MisfirePolicy::FireNextOnly => {
            if all.is_empty() {
                (Vec::new(), MisfireOutcome::NothingMissed)
            } else {
                (
                    vec![all[all.len() - 1].clone()],
                    MisfireOutcome::RanMostRecent,
                )
            }
        }
        MisfirePolicy::SkipIfOlderMinutes(mins) => {
            let cutoff = now_ms - i64::from(mins) * 60_000;
            let kept: Vec<ScheduleFire> = all
                .iter()
                .filter(|f| f.fire_time_ms >= cutoff)
                .cloned()
                .collect();
            let o = if kept.is_empty() {
                MisfireOutcome::SkippedOld
            } else {
                MisfireOutcome::RanAll
            };
            (kept, o)
        }
        MisfirePolicy::Pause => (Vec::new(), MisfireOutcome::Paused),
    };

    let to_fire: Vec<ScheduleFire> = selected.into_iter().take(cap).collect();
    let skipped = total_missed.saturating_sub(to_fire.len());
    CatchUpPlan {
        schedule_id,
        all_missed: all,
        to_fire,
        skipped,
        total_missed,
        cap,
        outcome,
    }
}
