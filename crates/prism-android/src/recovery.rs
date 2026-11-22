//! A bounded, trailing network-change throttle. No task exists when idle.
use std::time::Duration;
use tokio::{
    sync::mpsc,
    time::{sleep_until, Instant},
};

/// Reports local rebuild outcomes, never Internet reachability or error details
/// that could contain node credentials or destination names.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    state: &'static str,
    attempts: u64,
    failures: u64,
    reason: Option<&'static str>,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            state: "idle",
            attempts: 0,
            failures: 0,
            reason: None,
        }
    }
}
impl Report {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&mut self) {
        self.state = "rebuilding";
        self.attempts = self.attempts.saturating_add(1);
        self.reason = None;
    }
    pub fn finish(&mut self, failure: Option<Failure>) {
        self.state = if failure.is_some() { "failed" } else { "ready" };
        self.reason = failure.map(|f| match f {
            Failure::Geodata => "geodata-invalid",
            Failure::Timeout => "timeout",
            Failure::Reload => "reload-failed",
        });
        if failure.is_some() {
            self.failures = self.failures.saturating_add(1);
        }
    }
}
#[derive(Clone, Copy)]
pub enum Failure {
    Geodata,
    Timeout,
    Reload,
}

pub struct Changes {
    receiver: mpsc::Receiver<()>,
    next_allowed: Instant,
}
pub fn channel() -> (mpsc::Sender<()>, Changes) {
    let (sender, receiver) = mpsc::channel(1);
    (
        sender,
        Changes {
            receiver,
            next_allowed: Instant::now(),
        },
    )
}
impl Changes {
    /// The caller always awaits this inside the engine's stop/TUN select.
    /// Cancellation therefore means the whole engine is exiting.
    pub async fn next(&mut self) -> Option<()> {
        self.receiver.recv().await?;
        sleep_until(self.next_allowed).await;
        // Changes arriving during the cooldown belong to this same rebuild.
        // Changes during the rebuild itself queue one subsequent rebuild.
        // Capacity is one; drain at most one item so an unending producer
        // cannot starve the TUN/stop branch while we coalesce.
        let _ = self.receiver.try_recv();
        self.next_allowed = Instant::now() + Duration::from_secs(3);
        Some(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_distinguishes_rebuilding_failure_and_later_recovery() {
        let mut report = Report::new();
        assert_eq!(serde_json::to_value(&report).unwrap()["state"], "idle");
        for (i, failure) in [Failure::Geodata, Failure::Timeout, Failure::Reload]
            .into_iter()
            .enumerate()
        {
            report.begin();
            let pending = serde_json::to_value(&report).unwrap();
            assert_eq!(pending["state"], "rebuilding");
            assert!(pending["reason"].is_null());
            report.finish(Some(failure));
            let failed = serde_json::to_value(&report).unwrap();
            assert_eq!(failed["state"], "failed");
            assert_eq!(failed["failures"], i + 1);
            assert_eq!(
                failed["reason"],
                ["geodata-invalid", "timeout", "reload-failed"][i]
            );
        }
        report.begin();
        report.finish(None);
        let recovered = serde_json::to_value(&report).unwrap();
        assert_eq!(recovered["state"], "ready");
        assert_eq!(recovered["attempts"], 4);
        assert_eq!(recovered["failures"], 3);
        assert!(recovered["reason"].is_null());
        assert_eq!(serde_json::to_value(Report::new()).unwrap()["failures"], 0);
    }
    #[tokio::test(start_paused = true)]
    async fn last_change_inside_cooldown_is_delivered_without_another_event() {
        let (tx, mut changes) = channel();
        let start = Instant::now();
        tx.try_send(()).unwrap();
        assert_eq!(changes.next().await, Some(()));
        tokio::time::advance(Duration::from_millis(100)).await;
        tx.try_send(()).unwrap();
        let next = changes.next();
        tokio::pin!(next);
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut next)
            .await
            .is_err());
        assert_eq!(next.await, Some(()));
        assert_eq!(Instant::now() - start, Duration::from_secs(3));
    }
    #[tokio::test(start_paused = true)]
    async fn bursts_are_bounded_and_coalesced_without_extra_rebuilds() {
        let (tx, mut changes) = channel();
        tx.try_send(()).unwrap();
        changes.next().await.unwrap();
        tx.try_send(()).unwrap();
        let waiting = tokio::spawn(async move {
            changes.next().await.unwrap();
            changes
        });
        tokio::task::yield_now().await;
        tx.try_send(()).unwrap();
        for _ in 0..10000 {
            assert!(matches!(
                tx.try_send(()),
                Err(mpsc::error::TrySendError::Full(()))
            ));
        }
        let mut changes = waiting.await.unwrap();
        assert_eq!(tx.capacity(), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(10), changes.next())
                .await
                .is_err()
        );
        // A later event after idle remains immediately eligible.
        tx.try_send(()).unwrap();
        assert_eq!(changes.next().await, Some(()));
    }
    #[tokio::test(start_paused = true)]
    async fn dropping_the_engine_closes_delivery_and_new_sessions_start_fresh() {
        let (tx, mut changes) = channel();
        tx.try_send(()).unwrap();
        changes.next().await.unwrap();
        tx.try_send(()).unwrap();
        drop(changes);
        assert!(matches!(
            tx.try_send(()),
            Err(mpsc::error::TrySendError::Closed(()))
        ));
        let (new, mut changes) = channel();
        new.try_send(()).unwrap();
        let start = Instant::now();
        assert_eq!(changes.next().await, Some(()));
        assert_eq!(start, Instant::now());
    }
}
