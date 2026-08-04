use inputleap_protocol_legacy::RemoteMessage;

/// Platform input injection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    /// The requested event is not supported by this backend.
    UnsupportedEvent,
    /// The backend is unavailable on the current operating system.
    UnsupportedPlatform,
    /// The operating system rejected the injection request.
    OperatingSystem,
}

/// Backend boundary for events received from the legacy primary/server.
#[derive(Debug, Default)]
pub struct WindowsInputBackend;

fn normalize_absolute_coordinate(value: i16, extent: i16) -> i32 {
    if extent <= 1 {
        return 0;
    }
    let value = i32::from(value).clamp(0, i32::from(extent) - 1);
    value * 65_535 / (i32::from(extent) - 1)
}

impl WindowsInputBackend {
    /// Creates a Windows event-injection backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Injects one decoded legacy event into the local desktop.
    pub fn inject(&self, message: RemoteMessage) -> Result<(), InputError> {
        platform::inject(message)
    }
}

/// Failure to capture local desktop input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// The capture backend is unavailable on the current operating system.
    UnsupportedPlatform,
    /// The operating system rejected a capture query.
    OperatingSystem,
}

/// Polling capture of local Windows input.
///
/// The capture is state-based and bounded: each poll emits only transitions
/// observed since the previous poll. It does not install a global hook.
#[derive(Debug)]
pub struct WindowsInputCapture {
    platform: capture_platform::CaptureState,
}

impl WindowsInputCapture {
    /// Creates a capture state with no previously observed input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            platform: capture_platform::CaptureState::new(),
        }
    }

    /// Polls local input and returns legacy messages for observed transitions.
    pub fn poll(&mut self) -> Result<Vec<RemoteMessage>, CaptureError> {
        self.platform.poll()
    }

    /// Returns the primary desktop dimensions used by the one-peer topology.
    pub fn screen_size(&self) -> Result<(i16, i16), CaptureError> {
        self.platform.screen_size()
    }
}

impl Default for WindowsInputCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
mod platform {
    use super::InputError;
    use inputleap_protocol_legacy::RemoteMessage;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
        KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP, MOUSEINPUT, SendInput,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    pub fn inject(message: RemoteMessage) -> Result<(), InputError> {
        let input = match message {
            RemoteMessage::MouseMove { x, y } => mouse_move(x, y),
            RemoteMessage::MouseRelativeMove { dx, dy } => mouse_relative_move(dx, dy),
            RemoteMessage::MouseDown { button } => mouse_button(button, true)?,
            RemoteMessage::MouseUp { button } => mouse_button(button, false)?,
            RemoteMessage::KeyDown { button, .. } => key(button, false),
            RemoteMessage::KeyRepeat { button, .. } => key(button, false),
            RemoteMessage::KeyUp { button, .. } => key(button, true),
            _ => return Err(InputError::UnsupportedEvent),
        };
        send(input)
    }

    fn mouse_move(x: i16, y: i16) -> INPUT {
        let width = unsafe { GetSystemMetrics(SM_CXSCREEN) }.clamp(1, i32::from(i16::MAX)) as i16;
        let height = unsafe { GetSystemMetrics(SM_CYSCREEN) }.clamp(1, i32::from(i16::MAX)) as i16;
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: super::normalize_absolute_coordinate(x, width),
                    dy: super::normalize_absolute_coordinate(y, height),
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn mouse_relative_move(dx: i16, dy: i16) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: i32::from(dx),
                    dy: i32::from(dy),
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn mouse_button(button: u8, down: bool) -> Result<INPUT, InputError> {
        let flags = match (button, down) {
            (1, true) => MOUSEEVENTF_LEFTDOWN,
            (1, false) => MOUSEEVENTF_LEFTUP,
            (2, true) => MOUSEEVENTF_MIDDLEDOWN,
            (2, false) => MOUSEEVENTF_MIDDLEUP,
            (3, true) => MOUSEEVENTF_RIGHTDOWN,
            (3, false) => MOUSEEVENTF_RIGHTUP,
            _ => return Err(InputError::UnsupportedEvent),
        };
        Ok(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
    }

    fn key(button: u16, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: button,
                    dwFlags: KEYEVENTF_SCANCODE | if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn send(input: INPUT) -> Result<(), InputError> {
        let sent = unsafe { SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) };
        if sent == 1 {
            Ok(())
        } else {
            Err(InputError::OperatingSystem)
        }
    }
}

#[cfg(not(windows))]
mod capture_platform {
    use super::{CaptureError, RemoteMessage};

    #[derive(Debug)]
    pub struct CaptureState;

    impl CaptureState {
        pub const fn new() -> Self {
            Self
        }

        pub fn poll(&mut self) -> Result<Vec<RemoteMessage>, CaptureError> {
            Err(CaptureError::UnsupportedPlatform)
        }

        pub fn screen_size(&self) -> Result<(i16, i16), CaptureError> {
            Err(CaptureError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
mod capture_platform {
    use super::{CaptureError, RemoteMessage};
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, MAPVK_VK_TO_VSC, MapVirtualKeyW, VK_LBUTTON, VK_MBUTTON, VK_RBUTTON,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    const KEY_COUNT: usize = 256;

    #[derive(Debug)]
    pub struct CaptureState {
        cursor: Option<(i16, i16)>,
        buttons: [bool; 3],
        keys: [bool; KEY_COUNT],
    }

    impl CaptureState {
        pub const fn new() -> Self {
            Self {
                cursor: None,
                buttons: [false; 3],
                keys: [false; KEY_COUNT],
            }
        }

        pub fn poll(&mut self) -> Result<Vec<RemoteMessage>, CaptureError> {
            let mut messages = Vec::new();
            let mut point = POINT { x: 0, y: 0 };
            if unsafe { GetCursorPos(&mut point) } == 0 {
                return Err(CaptureError::OperatingSystem);
            }
            let x = point.x.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            let y = point.y.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            if self.cursor != Some((x, y)) {
                self.cursor = Some((x, y));
                messages.push(RemoteMessage::MouseMove { x, y });
            }

            for (index, virtual_key) in [VK_LBUTTON, VK_MBUTTON, VK_RBUTTON].into_iter().enumerate()
            {
                let pressed = key_pressed(virtual_key as i32);
                if pressed != self.buttons[index] {
                    self.buttons[index] = pressed;
                    messages.push(if pressed {
                        RemoteMessage::MouseDown {
                            button: (index + 1) as u8,
                        }
                    } else {
                        RemoteMessage::MouseUp {
                            button: (index + 1) as u8,
                        }
                    });
                }
            }

            for virtual_key in 0..KEY_COUNT {
                let pressed = key_pressed(virtual_key as i32);
                if pressed == self.keys[virtual_key] {
                    continue;
                }
                self.keys[virtual_key] = pressed;
                let scan = unsafe { MapVirtualKeyW(virtual_key as u32, MAPVK_VK_TO_VSC) } as u16;
                if scan == 0 {
                    continue;
                }
                messages.push(if pressed {
                    RemoteMessage::KeyDown {
                        key_id: scan,
                        modifier_mask: 0,
                        button: scan,
                    }
                } else {
                    RemoteMessage::KeyUp {
                        key_id: scan,
                        modifier_mask: 0,
                        button: scan,
                    }
                });
            }
            Ok(messages)
        }

        pub fn screen_size(&self) -> Result<(i16, i16), CaptureError> {
            let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
            let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
            if width <= 0 || height <= 0 {
                return Err(CaptureError::OperatingSystem);
            }
            Ok((
                width.clamp(1, i16::MAX as i32) as i16,
                height.clamp(1, i16::MAX as i32) as i16,
            ))
        }
    }

    fn key_pressed(virtual_key: i32) -> bool {
        (unsafe { GetAsyncKeyState(virtual_key) }) < 0
    }
}

#[cfg(not(windows))]
mod platform {
    use super::InputError;
    use inputleap_protocol_legacy::RemoteMessage;

    pub fn inject(_message: RemoteMessage) -> Result<(), InputError> {
        Err(InputError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use super::{CaptureError, WindowsInputCapture};
    use super::{InputError, WindowsInputBackend};
    use inputleap_protocol_legacy::RemoteMessage;

    #[test]
    fn absolute_coordinates_are_normalized_and_clamped() {
        assert_eq!(super::normalize_absolute_coordinate(0, 1920), 0);
        assert_eq!(super::normalize_absolute_coordinate(1919, 1920), 65_535);
        assert_eq!(super::normalize_absolute_coordinate(960, 1920), 32_784);
        assert_eq!(super::normalize_absolute_coordinate(-1, 1920), 0);
        assert_eq!(super::normalize_absolute_coordinate(2000, 1920), 65_535);
        assert_eq!(super::normalize_absolute_coordinate(10, 1), 0);
    }

    #[test]
    fn backend_accepts_only_input_messages_at_boundary() {
        let backend = WindowsInputBackend::new();
        let result = backend.inject(RemoteMessage::KeepAlive);
        assert_eq!(result, Err(InputError::UnsupportedEvent));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_backend_fails_closed() {
        let backend = WindowsInputBackend::new();
        let result = backend.inject(RemoteMessage::MouseMove { x: 1, y: 2 });
        assert_eq!(result, Err(InputError::UnsupportedPlatform));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_capture_fails_closed() {
        let mut capture = WindowsInputCapture::new();
        assert_eq!(capture.poll(), Err(CaptureError::UnsupportedPlatform));
    }
}
