//! Background work: writing usage counters to the store and forgetting expired limiter entries.

use std::time::Duration;

use tracing::{info, warn};

use crate::app::{AppState, now_millis};

/// Runs until the task is dropped.
pub async fn run(state: AppState) {
  let mut flush = tokio::time::interval(Duration::from_secs(
    state.config.database.flush_interval_secs.max(1),
  ));
  let mut sweep = tokio::time::interval(Duration::from_secs(60));
  let mut prune = tokio::time::interval(Duration::from_secs(3600));
  loop {
    tokio::select! {
      _ = flush.tick() => flush_usage(&state).await,
      _ = sweep.tick() => state.limiter.sweep(now_millis()),
      _ = prune.tick() => prune_unused(&state).await,
    }
  }
}

/// Deletes servers that registered and never pushed, so throwaway registrations don't keep
/// `max_servers` full.
async fn prune_unused(state: &AppState) {
  let days = state.config.database.prune_unused_after_days;
  if days == 0 {
    return;
  }
  let now_secs = i64::try_from(now_millis() / 1000).unwrap_or(i64::MAX);
  match state
    .store
    .prune_unused(now_secs - i64::from(days) * 86_400)
    .await
  {
    Ok(0) => {},
    Ok(removed) => info!(removed, "pruned servers that never pushed"),
    Err(error) => warn!(%error, "pruning unused servers failed"),
  }
}

/// Writes the counters since the last flush. Also called on shutdown.
pub async fn flush_usage(state: &AppState) {
  let drained = state.limiter.drain_pending();
  if drained.is_empty() {
    return;
  }
  let now_ms = now_millis();
  let mut by_day: std::collections::BTreeMap<i64, Vec<_>> = std::collections::BTreeMap::new();
  for (server_id, day, counts) in drained {
    by_day.entry(day).or_default().push((server_id, counts));
  }
  for (day, entries) in by_day {
    if let Err(error) = state
      .store
      .add_usage(entries, day, i64::try_from(now_ms / 1000).unwrap_or(i64::MAX))
      .await
    {
      warn!(%error, "writing usage counters failed");
    }
  }
}
