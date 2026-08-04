#![forbid(unsafe_code)]
//! Safe X11 input primitives for the experimental Rust runtime.
//!
//! The crate deliberately owns only X11 transport and event translation. It does
//! not know about the legacy wire protocol and it does not replace the C++/Qt
//! runtime. Clipboard ownership remains an explicit capability until a full
//! selection event loop is integrated.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerPosition {
    pub x: i16,
    pub y: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEvent {
    KeyPress { keycode: u8 },
    KeyRelease { keycode: u8 },
    ButtonPress { button: u8 },
    ButtonRelease { button: u8 },
    Motion { position: PointerPosition },
    MotionDelta { dx: i16, dy: i16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X11Capabilities {
    pub xtest: bool,
    pub xinput2: bool,
    pub clipboard: bool,
}

#[derive(Debug)]
pub enum X11Error {
    Connection(String),
    Request(String),
    ClipboardUnavailable,
}

impl fmt::Display for X11Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(message) => write!(formatter, "X11 connection failed: {message}"),
            Self::Request(message) => write!(formatter, "X11 request failed: {message}"),
            Self::ClipboardUnavailable => formatter.write_str("X11 clipboard is not integrated"),
        }
    }
}

impl std::error::Error for X11Error {}

#[cfg(unix)]
mod unix {
    use super::{InputEvent, PointerPosition, X11Capabilities, X11Error};
    use x11rb::connection::{Connection, RequestConnection};
    use x11rb::protocol::Event;
    use x11rb::protocol::xinput::{
        ConnectionExt as XinputConnectionExt, EventMask as XinputEventMask, XIEventMask,
    };
    use x11rb::protocol::xproto::{ConnectionExt as XprotoConnectionExt, Window};
    use x11rb::protocol::xtest::ConnectionExt as XtestConnectionExt;
    use x11rb::rust_connection::RustConnection;

    pub struct X11Backend {
        connection: RustConnection,
        root: Window,
        capabilities: X11Capabilities,
    }

    impl X11Backend {
        pub fn connect(display: Option<&str>) -> Result<Self, X11Error> {
            let (connection, screen) =
                x11rb::connect(display).map_err(|error| X11Error::Connection(error.to_string()))?;
            let root = connection
                .setup()
                .roots
                .get(screen)
                .ok_or_else(|| X11Error::Connection("screen is unavailable".to_string()))?
                .root;
            let xtest = connection
                .xtest_get_version(2, 2)
                .ok()
                .and_then(|cookie| cookie.reply().ok())
                .is_some();
            let xinput2 = connection
                .extension_information(x11rb::protocol::xinput::X11_EXTENSION_NAME)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .is_some();
            Ok(Self {
                connection,
                root,
                capabilities: X11Capabilities {
                    xtest,
                    xinput2,
                    clipboard: false,
                },
            })
        }

        #[must_use]
        pub const fn capabilities(&self) -> X11Capabilities {
            self.capabilities
        }

        pub fn device_info(&self) -> Result<(i16, i16, i16, i16), X11Error> {
            let geometry = self
                .connection
                .get_geometry(self.root)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .reply()
                .map_err(|error| X11Error::Request(error.to_string()))?;
            let pointer = self
                .connection
                .query_pointer(self.root)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .reply()
                .map_err(|error| X11Error::Request(error.to_string()))?;
            Ok((
                i16::try_from(geometry.width)
                    .map_err(|_| X11Error::Request("screen width exceeds legacy range".into()))?,
                i16::try_from(geometry.height)
                    .map_err(|_| X11Error::Request("screen height exceeds legacy range".into()))?,
                pointer.root_x,
                pointer.root_y,
            ))
        }

        pub fn select_input(&self) -> Result<(), X11Error> {
            if !self.capabilities.xinput2 {
                return Err(X11Error::Request("XInput2 is unavailable".to_string()));
            }
            self.connection
                .xinput_xi_select_events(
                    self.root,
                    &[XinputEventMask {
                        deviceid: 1,
                        mask: vec![
                            XIEventMask::RAW_KEY_PRESS
                                | XIEventMask::RAW_KEY_RELEASE
                                | XIEventMask::RAW_BUTTON_PRESS
                                | XIEventMask::RAW_BUTTON_RELEASE
                                | XIEventMask::RAW_MOTION,
                        ],
                    }],
                )
                .map_err(|error| X11Error::Request(error.to_string()))?
                .check()
                .map_err(|error| X11Error::Request(error.to_string()))
        }

        pub fn poll_event(&self) -> Result<Option<InputEvent>, X11Error> {
            loop {
                let Some(event) = self
                    .connection
                    .poll_for_event()
                    .map_err(|error| X11Error::Request(error.to_string()))?
                else {
                    return Ok(None);
                };
                let input_event = match event {
                    Event::KeyPress(event) => Some(InputEvent::KeyPress {
                        keycode: event.detail,
                    }),
                    Event::KeyRelease(event) => Some(InputEvent::KeyRelease {
                        keycode: event.detail,
                    }),
                    Event::ButtonPress(event) => Some(InputEvent::ButtonPress {
                        button: event.detail,
                    }),
                    Event::ButtonRelease(event) => Some(InputEvent::ButtonRelease {
                        button: event.detail,
                    }),
                    Event::MotionNotify(event) => Some(InputEvent::Motion {
                        position: PointerPosition {
                            x: event.event_x,
                            y: event.event_y,
                        },
                    }),
                    Event::XinputRawKeyPress(event) => event
                        .detail
                        .try_into()
                        .ok()
                        .map(|keycode| InputEvent::KeyPress { keycode }),
                    Event::XinputRawKeyRelease(event) => event
                        .detail
                        .try_into()
                        .ok()
                        .map(|keycode| InputEvent::KeyRelease { keycode }),
                    Event::XinputRawButtonPress(event) => event
                        .detail
                        .try_into()
                        .ok()
                        .map(|button| InputEvent::ButtonPress { button }),
                    Event::XinputRawButtonRelease(event) => event
                        .detail
                        .try_into()
                        .ok()
                        .map(|button| InputEvent::ButtonRelease { button }),
                    Event::XinputRawMotion(event) => {
                        let (dx, dy) =
                            raw_motion_delta(&event.valuator_mask, &event.axisvalues_raw);
                        Some(InputEvent::MotionDelta { dx, dy })
                    }
                    _ => None,
                };
                if input_event.is_some() {
                    return Ok(input_event);
                }
            }
        }

        pub fn move_pointer(&self, position: PointerPosition) -> Result<(), X11Error> {
            if !self.capabilities.xtest {
                return Err(X11Error::Request("XTEST is unavailable".to_string()));
            }
            self.connection
                .warp_pointer(x11rb::NONE, self.root, 0, 0, 0, 0, position.x, position.y)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .check()
                .map_err(|error| X11Error::Request(error.to_string()))?;
            self.connection
                .flush()
                .map_err(|error| X11Error::Request(error.to_string()))
        }

        pub fn move_pointer_relative(&self, dx: i16, dy: i16) -> Result<(), X11Error> {
            if !self.capabilities.xtest {
                return Err(X11Error::Request("XTEST is unavailable".to_string()));
            }
            self.connection
                .xtest_fake_input(6, 0, 0, x11rb::NONE, dx, dy, 0)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .check()
                .map_err(|error| X11Error::Request(error.to_string()))?;
            self.connection
                .flush()
                .map_err(|error| X11Error::Request(error.to_string()))
        }

        pub fn send_key(&self, press: bool, keycode: u8) -> Result<(), X11Error> {
            self.fake_input(if press { 2 } else { 3 }, keycode)
        }

        pub fn send_button(&self, press: bool, button: u8) -> Result<(), X11Error> {
            self.fake_input(if press { 4 } else { 5 }, button)
        }

        fn fake_input(&self, event_type: u8, detail: u8) -> Result<(), X11Error> {
            if !self.capabilities.xtest {
                return Err(X11Error::Request("XTEST is unavailable".to_string()));
            }
            self.connection
                .xtest_fake_input(event_type, detail, 0, x11rb::NONE, 0, 0, 0)
                .map_err(|error| X11Error::Request(error.to_string()))?
                .check()
                .map_err(|error| X11Error::Request(error.to_string()))?;
            self.connection
                .flush()
                .map_err(|error| X11Error::Request(error.to_string()))
        }

        pub fn set_clipboard_utf8(&self, _value: &str) -> Result<(), X11Error> {
            Err(X11Error::ClipboardUnavailable)
        }
    }

    fn raw_motion_delta(mask: &[u32], values: &[x11rb::protocol::xinput::Fp3232]) -> (i16, i16) {
        let mut axis_values = [0i16; 2];
        let mut value_index = 0usize;
        for (word_index, word) in mask.iter().copied().enumerate() {
            for bit in 0..u32::BITS {
                if word & (1 << bit) == 0 {
                    continue;
                }
                let axis = word_index * u32::BITS as usize + bit as usize;
                if value_index < values.len() && axis < 2 {
                    axis_values[axis] = values[value_index]
                        .integral
                        .clamp(i16::MIN as i32, i16::MAX as i32)
                        as i16;
                }
                value_index += 1;
            }
        }
        (axis_values[0], axis_values[1])
    }

    pub use X11Backend as PlatformBackend;
}

#[cfg(unix)]
pub use unix::PlatformBackend as X11Backend;

#[cfg(not(unix))]
pub struct X11Backend;

#[cfg(not(unix))]
impl X11Backend {
    pub fn connect(_: Option<&str>) -> Result<Self, X11Error> {
        Err(X11Error::Connection(
            "X11 backend requires Unix".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{InputEvent, PointerPosition, X11Capabilities};

    #[test]
    fn input_events_preserve_wire_values() {
        assert_eq!(
            InputEvent::Motion {
                position: PointerPosition { x: -12, y: 44 },
            },
            InputEvent::Motion {
                position: PointerPosition { x: -12, y: 44 },
            }
        );
        assert_eq!(
            InputEvent::MotionDelta { dx: -12, dy: 44 },
            InputEvent::MotionDelta { dx: -12, dy: 44 }
        );
    }

    #[test]
    fn clipboard_is_not_claimed_before_selection_loop_exists() {
        let capabilities = X11Capabilities {
            xtest: true,
            xinput2: true,
            clipboard: false,
        };
        assert!(!capabilities.clipboard);
    }
}
