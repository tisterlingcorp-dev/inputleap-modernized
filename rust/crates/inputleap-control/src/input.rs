//! Native Windows pilot event contract and bounded, order-preserving queue.
//! Independent of the legacy protocol's signed 16-bit desktop coordinates.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEvent {
    AbsoluteMove {
        x: i32,
        y: i32,
    },
    RelativeMove {
        dx: i32,
        dy: i32,
    },
    Key {
        scan_code: u16,
        extended: bool,
        released: bool,
    },
    Button {
        button: MouseButton,
        released: bool,
    },
    Wheel {
        horizontal: bool,
        delta: i32,
    },
    EnterScreen,
    LeaveScreen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    Overflow,
    ResetRequired,
}

/// Callbacks enqueue without blocking or growing the initial allocation. An
/// overflow poisons the queue: the session must stop, release pressed inputs and
/// create a fresh queue, never silently discard a key/button transition.
#[derive(Debug)]
pub struct InputQueue {
    queue: VecDeque<InputEvent>,
    capacity: usize,
    poisoned: bool,
}

impl InputQueue {
    pub fn new(capacity: usize) -> Option<Self> {
        (1..=4096).contains(&capacity).then(|| Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            poisoned: false,
        })
    }

    pub fn push(&mut self, event: InputEvent) -> Result<(), QueueError> {
        if self.poisoned {
            return Err(QueueError::ResetRequired);
        }
        // Raw relative counts cannot be summed safely: Windows pointer
        // acceleration can make two deltas differ from one combined delta.
        // Only consecutive absolute positions in the same screen epoch coalesce.
        if let Some(last @ InputEvent::AbsoluteMove { .. }) = self.queue.back_mut()
            && matches!(event, InputEvent::AbsoluteMove { .. })
        {
            *last = event;
            return Ok(());
        }
        if self.queue.len() == self.capacity {
            self.poisoned = true;
            return Err(QueueError::Overflow);
        }
        self.queue.push_back(event);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<Option<InputEvent>, QueueError> {
        if self.poisoned {
            return Err(QueueError::ResetRequired);
        }
        Ok(self.queue.pop_front())
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_moves_coalesce_but_never_across_key_boundaries() {
        let mut queue = InputQueue::new(3).unwrap();
        for x in -100_000..100_000 {
            queue.push(InputEvent::AbsoluteMove { x, y: -20 }).unwrap();
        }
        let key = InputEvent::Key {
            scan_code: 0x1d,
            extended: true,
            released: false,
        };
        queue.push(key).unwrap();
        queue
            .push(InputEvent::AbsoluteMove { x: 200_000, y: 0 })
            .unwrap();
        assert_eq!(queue.pending(), 3);
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::AbsoluteMove { x: 99_999, y: -20 })
        );
        assert_eq!(queue.pop().unwrap(), Some(key));
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::AbsoluteMove { x: 200_000, y: 0 })
        );
    }

    #[test]
    fn relative_moves_preserve_individual_counts_and_do_not_saturate() {
        let mut queue = InputQueue::new(2).unwrap();
        queue
            .push(InputEvent::RelativeMove { dx: 2, dy: -3 })
            .unwrap();
        queue
            .push(InputEvent::RelativeMove { dx: -1, dy: 4 })
            .unwrap();
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::RelativeMove { dx: 2, dy: -3 })
        );
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::RelativeMove { dx: -1, dy: 4 })
        );
        queue
            .push(InputEvent::RelativeMove {
                dx: i32::MAX,
                dy: 0,
            })
            .unwrap();
        queue
            .push(InputEvent::RelativeMove { dx: 1, dy: 0 })
            .unwrap();
        assert_eq!(queue.pending(), 2);
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::RelativeMove {
                dx: i32::MAX,
                dy: 0
            })
        );
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::RelativeMove { dx: 1, dy: 0 })
        );
    }

    #[test]
    fn screen_transitions_separate_absolute_move_epochs() {
        let mut queue = InputQueue::new(3).unwrap();
        for transition in [InputEvent::EnterScreen, InputEvent::LeaveScreen] {
            let before = InputEvent::AbsoluteMove { x: -30_000, y: 0 };
            let after = InputEvent::AbsoluteMove { x: 90_000, y: 0 };
            queue.push(before).unwrap();
            queue.push(transition).unwrap();
            queue.push(after).unwrap();
            assert_eq!(queue.pop().unwrap(), Some(before));
            assert_eq!(queue.pop().unwrap(), Some(transition));
            assert_eq!(queue.pop().unwrap(), Some(after));
        }
    }

    #[test]
    fn overflow_requires_session_reset_instead_of_losing_releases() {
        let mut queue = InputQueue::new(1).unwrap();
        queue
            .push(InputEvent::Button {
                button: MouseButton::Left,
                released: false,
            })
            .unwrap();
        assert_eq!(
            queue.push(InputEvent::Button {
                button: MouseButton::Left,
                released: true
            }),
            Err(QueueError::Overflow)
        );
        assert_eq!(queue.pop(), Err(QueueError::ResetRequired));
        assert_eq!(
            queue.push(InputEvent::LeaveScreen),
            Err(QueueError::ResetRequired)
        );
        assert!(InputQueue::new(0).is_none());
        assert!(InputQueue::new(4097).is_none());
    }
}
