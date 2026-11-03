//! Pure lifecycle policy; does not launch processes or grant Windows permissions.

use std::collections::VecDeque;
use std::time::Duration;

/// Backoff capped at 30 seconds. Caller supplies OS randomness (0..=250 ms).
#[derive(Debug, Default)]
pub struct ReconnectBackoff {
    failures: u8,
}

impl ReconnectBackoff {
    pub fn next_delay(&mut self, jitter_ms: u8) -> Duration {
        let seconds = [1, 2, 4, 8, 16, 30][usize::from(self.failures.min(5))];
        self.failures = self.failures.saturating_add(1);
        (Duration::from_secs(seconds) + Duration::from_millis(u64::from(jitter_ms.min(250))))
            .min(Duration::from_secs(30))
    }

    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerHealth {
    Healthy,
    WrongSession,
    InvalidProgress,
    HeartbeatTimeout,
    InputStalled,
}

/// Monotonic timestamps and processing acknowledgements distinguish an idle
/// worker from one that is alive but no longer processing pending input.
#[derive(Debug)]
pub struct WorkerProgress {
    session: u32,
    sent: u64,
    processed: u64,
    heartbeat_at: Duration,
    progress_at: Duration,
}

impl WorkerProgress {
    pub fn new(session: u32, now: Duration) -> Option<Self> {
        (session != 0).then_some(Self {
            session,
            sent: 0,
            processed: 0,
            heartbeat_at: now,
            progress_at: now,
        })
    }

    pub fn sent(&mut self, sequence: u64, now: Duration) -> bool {
        if sequence <= self.sent || now < self.progress_at || now < self.heartbeat_at {
            return false;
        }
        if self.sent == self.processed {
            self.progress_at = now;
        }
        self.sent = sequence;
        true
    }

    pub fn acknowledge(&mut self, session: u32, sequence: u64, now: Duration) -> WorkerHealth {
        if session != self.session {
            return WorkerHealth::WrongSession;
        }
        if sequence < self.processed
            || sequence > self.sent
            || now < self.heartbeat_at
            || now < self.progress_at
        {
            return WorkerHealth::InvalidProgress;
        }
        self.heartbeat_at = now;
        if sequence > self.processed {
            self.processed = sequence;
            self.progress_at = now;
        }
        WorkerHealth::Healthy
    }

    pub fn health(&self, now: Duration, timeout: Duration) -> WorkerHealth {
        if now.saturating_sub(self.heartbeat_at) > timeout {
            WorkerHealth::HeartbeatTimeout
        } else if self.sent != self.processed && now.saturating_sub(self.progress_at) > timeout {
            WorkerHealth::InputStalled
        } else {
            WorkerHealth::Healthy
        }
    }
}

/// At most three worker restarts in any rolling minute. Network retries do not
/// consume this budget: a reachable process must not restart on every packet loss.
#[derive(Debug, Default)]
pub struct RestartBudget {
    restarts: VecDeque<Duration>,
}

impl RestartBudget {
    pub fn allow(&mut self, now: Duration) -> bool {
        if self.restarts.back().is_some_and(|previous| now < *previous) {
            return false;
        }
        while self
            .restarts
            .front()
            .is_some_and(|previous| now.saturating_sub(*previous) >= Duration::from_secs(60))
        {
            self.restarts.pop_front();
        }
        if self.restarts.len() == 3 {
            return false;
        }
        self.restarts.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn seconds(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    #[test]
    fn backoff_caps_and_resets() {
        let mut policy = ReconnectBackoff::default();
        for expected in [1, 2, 4, 8, 16, 30, 30, 30] {
            assert_eq!(policy.next_delay(0), seconds(expected));
        }
        policy.reset();
        assert_eq!(policy.next_delay(250), Duration::from_millis(1250));
    }

    #[test]
    fn idle_heartbeat_is_healthy_but_stalled_input_is_not() {
        let mut worker = WorkerProgress::new(1, seconds(0)).unwrap();
        assert_eq!(worker.acknowledge(1, 0, seconds(10)), WorkerHealth::Healthy);
        assert_eq!(
            worker.health(seconds(10), seconds(5)),
            WorkerHealth::Healthy
        );
        assert!(worker.sent(1, seconds(10)));
        assert_eq!(worker.acknowledge(1, 0, seconds(16)), WorkerHealth::Healthy);
        assert_eq!(
            worker.health(seconds(16), seconds(5)),
            WorkerHealth::InputStalled
        );
        assert_eq!(worker.acknowledge(1, 1, seconds(17)), WorkerHealth::Healthy);
        assert_eq!(
            worker.health(seconds(17), seconds(5)),
            WorkerHealth::Healthy
        );
    }

    #[test]
    fn wrong_sessions_and_unissued_acknowledgements_cannot_keep_worker_alive() {
        assert!(WorkerProgress::new(0, seconds(0)).is_none());
        let mut worker = WorkerProgress::new(1, seconds(0)).unwrap();
        assert_eq!(
            worker.acknowledge(2, 0, seconds(4)),
            WorkerHealth::WrongSession
        );
        assert_eq!(
            worker.acknowledge(1, 99, seconds(4)),
            WorkerHealth::InvalidProgress
        );
        assert_eq!(
            worker.health(seconds(6), seconds(5)),
            WorkerHealth::HeartbeatTimeout
        );
    }

    #[test]
    fn restart_storm_is_limited_and_recovers_after_window() {
        let mut budget = RestartBudget::default();
        for value in [0, 1, 2] {
            assert!(budget.allow(seconds(value)));
        }
        assert!(!budget.allow(seconds(3)));
        assert!(!budget.allow(seconds(1)));
        assert!(budget.allow(seconds(60)));
        assert!(!budget.allow(seconds(60)));
        assert!(budget.allow(seconds(61)));
    }
}
