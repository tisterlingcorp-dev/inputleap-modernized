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
        if let Some(last) = self.queue.back_mut() {
            match (*last, event) {
                (InputEvent::AbsoluteMove { .. }, InputEvent::AbsoluteMove { .. }) => {
                    *last = event;
                    return Ok(());
                }
                (
                    InputEvent::RelativeMove {
                        dx: old_x,
                        dy: old_y,
                    },
                    InputEvent::RelativeMove { dx, dy },
                ) => {
                    if let (Some(dx), Some(dy)) = (old_x.checked_add(dx), old_y.checked_add(dy)) {
                        *last = InputEvent::RelativeMove { dx, dy };
                        return Ok(());
                    }
                }
                _ => {}
            }
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
    fn relative_moves_preserve_displacement_and_do_not_saturate() {
        let mut queue = InputQueue::new(2).unwrap();
        queue
            .push(InputEvent::RelativeMove { dx: 2, dy: -3 })
            .unwrap();
        queue
            .push(InputEvent::RelativeMove { dx: -1, dy: 4 })
            .unwrap();
        assert_eq!(
            queue.pop().unwrap(),
            Some(InputEvent::RelativeMove { dx: 1, dy: 1 })
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
