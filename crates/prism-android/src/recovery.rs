//! A bounded, trailing network-change throttle. No task exists when idle.
use std::time::Duration;
use tokio::{
    sync::mpsc,
    time::{sleep_until, Instant},
};

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
