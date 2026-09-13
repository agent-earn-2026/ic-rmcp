//! Prometheus Usage Beacon — a Rust port of the Motoko `Beacon.mo` module.
//!
//! Accumulates per-caller, per-tool usage counters and periodically flushes
//! them to the Prometheus UsageTracker canister via an inter-canister call.
//!
//! The public API mirrors the Motoko version: `init`, `track_call`,
//! `start_timer`. `send_beacon` flattens the accumulated usage data, posts it
//! to the tracker canister, and resets local state.

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::{call::call, time};
use ic_cdk_timers::TimerId;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

/// One caller's usage of a single tool within a reporting window.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CallerActivity {
    pub caller: Principal,
    pub tool_id: String,
    pub call_count: u64,
}

/// The payload sent to the UsageTracker canister.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UsageStats {
    pub start_timestamp_ns: u64,
    pub end_timestamp_ns: u64,
    pub activity: Vec<CallerActivity>,
}

/// Beacon state: accumulated usage plus timer/config.
pub struct BeaconContext {
    /// usage_data[caller][tool_id] = call_count
    pub usage_data: HashMap<Principal, HashMap<String, u64>>,
    /// The active recurring timer, if started.
    pub timer_id: Option<TimerId>,
    /// Timestamp (ns) of the last successful beacon transmission.
    pub last_send_timestamp_ns: u64,
    /// The UsageTracker canister that receives reports.
    pub tracker_canister_id: Principal,
    /// Reporting interval in seconds (default 1 hour).
    pub reporting_interval_seconds: u64,
}

thread_local! {
    static BEACON: RefCell<Option<BeaconContext>> = RefCell::new(None);
}

/// Create a fresh beacon context. Call once at canister init.
pub fn init(tracker_canister_id: Principal, reporting_interval_seconds: Option<u64>) {
    BEACON.with_borrow_mut(|b| {
        *b = Some(BeaconContext {
            usage_data: HashMap::new(),
            timer_id: None,
            last_send_timestamp_ns: 0,
            tracker_canister_id,
            reporting_interval_seconds: reporting_interval_seconds.unwrap_or(60 * 60),
        });
    });
}

/// Track a single tool invocation by `caller`.
pub fn track_call(caller: Principal, tool_id: &str) {
    BEACON.with_borrow_mut(|b| {
        if let Some(ctx) = b.as_mut() {
            *ctx.usage_data
                .entry(caller)
                .or_default()
                .entry(tool_id.to_string())
                .or_insert(0) += 1;
        }
    });
}

/// Flatten accumulated usage into a `UsageStats` payload and reset state.
/// `now_ns` is the current timestamp in nanoseconds (passed in for testability).
fn drain_usage(ctx: &mut BeaconContext, now_ns: u64) -> Option<UsageStats> {
    if ctx.usage_data.is_empty() {
        return None;
    }
    let start = ctx.last_send_timestamp_ns;
    let end = now_ns;
    ctx.last_send_timestamp_ns = end;

    let data = std::mem::take(&mut ctx.usage_data);
    let mut activity = Vec::new();
    for (caller, tools) in data {
        for (tool_id, call_count) in tools {
            activity.push(CallerActivity {
                caller,
                tool_id,
                call_count,
            });
        }
    }
    Some(UsageStats {
        start_timestamp_ns: start,
        end_timestamp_ns: end,
        activity,
    })
}

/// Send the accumulated usage beacon to the tracker canister.
///
/// Flattens usage data, performs the inter-canister `log_call`, and resets
/// local state. Errors are logged, not fatal.
pub async fn send_beacon() -> Result<(), String> {
    let (tracker_id, stats) = BEACON.with_borrow_mut(|b| {
        let ctx = b.as_mut().ok_or("beacon not initialized")?;
        match drain_usage(ctx, time()) {
            Some(s) => Ok((ctx.tracker_canister_id, s)),
            None => Err("no usage data".to_string()),
        }
    })?;

    let _: (Result<(), String>,) = call(tracker_id, "log_call", (stats,))
        .await
        .map_err(|e| format!("beacon send failed: {e:?}"))?;
    Ok(())
}

/// Start the recurring beacon timer. Cancels any existing timer first.
///
/// Uses `ic_cdk_timers::set_timer_interval` to schedule `send_beacon`.
pub fn start_timer() {
    let interval = BEACON.with_borrow(|b| {
        b.as_ref()
            .map(|c| c.reporting_interval_seconds)
            .unwrap_or(3600)
    });

    // Cancel any pre-existing timer.
    BEACON.with_borrow_mut(|b| {
        if let Some(ctx) = b.as_mut() {
            if let Some(id) = ctx.timer_id.take() {
                ic_cdk_timers::clear_timer(id);
            }
            ctx.last_send_timestamp_ns = time();
        }
    });

    let id = ic_cdk_timers::set_timer_interval(Duration::from_secs(interval), || {
        ic_cdk::spawn(async {
            let _ = send_beacon().await;
        });
    });

    BEACON.with_borrow_mut(|b| {
        if let Some(ctx) = b.as_mut() {
            ctx.timer_id = Some(id);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    fn setup() {
        init(principal(9), Some(60));
    }

    #[test]
    fn track_call_accumulates_counts() {
        setup();
        let alice = principal(1);
        track_call(alice, "search");
        track_call(alice, "search");
        track_call(alice, "fetch");

        BEACON.with_borrow(|b| {
            let ctx = b.as_ref().unwrap();
            assert_eq!(ctx.usage_data[&alice]["search"], 2);
            assert_eq!(ctx.usage_data[&alice]["fetch"], 1);
        });
    }

    #[test]
    fn drain_flattens_and_resets() {
        setup();
        let alice = principal(1);
        let bob = principal(2);
        track_call(alice, "a");
        track_call(alice, "a");
        track_call(bob, "b");

        let stats = BEACON
            .with_borrow_mut(|b| drain_usage(b.as_mut().unwrap(), 1_000_000))
            .unwrap();
        assert_eq!(stats.activity.len(), 2);
        // state reset
        BEACON.with_borrow(|b| assert!(b.as_ref().unwrap().usage_data.is_empty()));
    }

    #[test]
    fn drain_empty_returns_none() {
        setup();
        let r = BEACON.with_borrow_mut(|b| drain_usage(b.as_mut().unwrap(), 1_000_000));
        assert!(r.is_none());
    }
}
