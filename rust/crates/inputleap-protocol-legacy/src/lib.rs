#![forbid(unsafe_code)]
#![doc = "Fail-closed parsing for the legacy Input Leap remote protocol."]

/// Maximum accepted remote frame payload: 4 MiB.
pub const MAX_PAYLOAD_LENGTH: usize = 4 * 1024 * 1024;
/// Maximum accepted legacy byte string: 1 MiB.
pub const MAX_STRING_LENGTH: usize = 1024 * 1024;
/// Maximum complete hello-back payload, including code, version, and name field.
pub const MAX_HELLO_BACK_LENGTH: usize = 1024;
/// Supported legacy protocol major version.
pub const SUPPORTED_MAJOR_VERSION: i16 = 1;
/// Supported legacy protocol minor version.
pub const SUPPORTED_MINOR_VERSION: i16 = 6;

const HANDSHAKE_CODE: &[u8; 7] = b"Barrier";
const FRAME_PREFIX_LENGTH: usize = 4;
const VERSION_LENGTH: usize = 4;
const HELLO_LENGTH: usize = HANDSHAKE_CODE.len() + VERSION_LENGTH;
/// Fixed width of a legacy remote message code.
pub const REMOTE_MESSAGE_CODE_LENGTH: usize = 4;
const REMOTE_NOOP_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CNOP";
const REMOTE_KEEP_ALIVE_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CALV";
const REMOTE_QUERY_INFO_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"QINF";
const REMOTE_INFO_ACK_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CIAK";
const REMOTE_RESET_OPTIONS_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CROP";
const REMOTE_LEAVE_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"COUT";
const REMOTE_CLOSE_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CBYE";
const REMOTE_BUSY_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"EBSY";
const REMOTE_UNKNOWN_CLIENT_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"EUNK";
const REMOTE_BAD_PROTOCOL_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"EBAD";
const REMOTE_INCOMPATIBLE_VERSION_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"EICV";
const REMOTE_INCOMPATIBLE_VERSION_LENGTH: usize = 8;
const REMOTE_SCREEN_SAVER_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"CSEC";
const REMOTE_SCREEN_SAVER_LENGTH: usize = 5;
const REMOTE_MOUSE_DOWN_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DMDN";
const REMOTE_MOUSE_UP_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DMUP";
const REMOTE_MOUSE_BUTTON_LENGTH: usize = 5;
const REMOTE_MOUSE_MOVE_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DMMV";
const REMOTE_MOUSE_MOVE_LENGTH: usize = 8;
const REMOTE_MOUSE_RELATIVE_MOVE_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DMRM";
const REMOTE_MOUSE_RELATIVE_MOVE_LENGTH: usize = 8;
const REMOTE_DEVICE_INFO_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DINF";
const REMOTE_DEVICE_INFO_LENGTH: usize = 18;
const REMOTE_KEY_DOWN_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DKDN";
const REMOTE_KEY_DOWN_LENGTH: usize = 10;
const REMOTE_KEY_REPEAT_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DKRP";
const REMOTE_KEY_REPEAT_LENGTH: usize = 12;
const REMOTE_KEY_UP_CODE: &[u8; REMOTE_MESSAGE_CODE_LENGTH] = b"DKUP";
const REMOTE_KEY_UP_LENGTH: usize = 10;

/// Stable, normalized parser result category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    /// The framing or expected handshake was accepted.
    Accepted,
    /// The stream does not yet contain a complete outer frame.
    NeedMore,
    /// Complete input is invalid for the current parser or handshake state.
    Malformed,
    /// A declared frame or string length exceeds its limit.
    Oversized,
    /// The handshake is well formed but its version is not supported in this direction.
    UnsupportedVersion,
}

/// Handshake variant required by the caller's current protocol state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedHandshake {
    /// Server greeting received by the C++ client.
    Hello,
    /// Client response received by the C++ server.
    HelloBack,
}

/// A borrowed, decoded legacy handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Handshake<'a> {
    /// Server greeting containing only the protocol version.
    Hello {
        /// Protocol major version.
        major: i16,
        /// Protocol minor version.
        minor: i16,
    },
    /// Client greeting containing the protocol version and raw legacy name bytes.
    HelloBack {
        /// Protocol major version.
        major: i16,
        /// Protocol minor version.
        minor: i16,
        /// Raw client-name bytes; legacy names are not required to be UTF-8.
        client_name: &'a [u8],
    },
}

/// Wire direction of a remote protocol message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMessageDirection {
    /// Message emitted by the secondary/client and consumed by the primary/server.
    ClientToServer,
    /// Message emitted by the primary/server and consumed by the secondary/client.
    ServerToClient,
}

/// Receiver state in which a remote protocol message is processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMessageState {
    /// The C++ client-side `ServerProxy` is still parsing handshake messages.
    ClientHandshake,
    /// The C++ server-side `ClientProxyUnknown` still expects the hello-back greeting.
    ServerAwaitingHelloBack,
    /// The C++ server-side `ClientProxy1_6` has accepted hello-back and still expects `DINF`.
    ServerAwaitingInfo,
    /// The receiver has entered its established protocol parser.
    Active,
}

/// Explicit wire direction and receiver state for a remote message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteMessageContext {
    direction: RemoteMessageDirection,
    state: RemoteMessageState,
}

impl RemoteMessageContext {
    /// Creates an explicit remote-message context.
    #[must_use]
    pub const fn new(direction: RemoteMessageDirection, state: RemoteMessageState) -> Self {
        Self { direction, state }
    }

    const fn allows_noop_decode(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::ClientHandshake | RemoteMessageState::Active
            ) | (
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::ServerAwaitingInfo | RemoteMessageState::Active
            )
        )
    }

    const fn allows_noop_encode(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_keep_alive_decode(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::ClientHandshake | RemoteMessageState::Active
            ) | (
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_keep_alive_encode(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            ) | (
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::ServerAwaitingInfo | RemoteMessageState::Active
            )
        )
    }

    const fn allows_fixed_control_decode(self, message: RemoteMessage) -> bool {
        match message {
            RemoteMessage::QueryInfo | RemoteMessage::InfoAck | RemoteMessage::ResetOptions => {
                matches!(
                    (self.direction, self.state),
                    (
                        RemoteMessageDirection::ServerToClient,
                        RemoteMessageState::ClientHandshake | RemoteMessageState::Active
                    )
                )
            }
            RemoteMessage::Leave => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::Active
                )
            ),
            RemoteMessage::Noop
            | RemoteMessage::KeepAlive
            | RemoteMessage::Close
            | RemoteMessage::Busy
            | RemoteMessage::UnknownClient
            | RemoteMessage::BadProtocol
            | RemoteMessage::IncompatibleVersion { .. }
            | RemoteMessage::ScreenSaver { .. }
            | RemoteMessage::MouseDown { .. }
            | RemoteMessage::MouseUp { .. }
            | RemoteMessage::MouseMove { .. }
            | RemoteMessage::MouseRelativeMove { .. }
            | RemoteMessage::DeviceInfo { .. }
            | RemoteMessage::KeyDown { .. }
            | RemoteMessage::KeyRepeat { .. }
            | RemoteMessage::KeyUp { .. } => false,
        }
    }

    const fn allows_fixed_control_encode(self, message: RemoteMessage) -> bool {
        match message {
            RemoteMessage::QueryInfo => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::ClientHandshake
                )
            ),
            RemoteMessage::InfoAck | RemoteMessage::ResetOptions => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::ClientHandshake | RemoteMessageState::Active
                )
            ),
            RemoteMessage::Leave => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::Active
                )
            ),
            RemoteMessage::Noop
            | RemoteMessage::KeepAlive
            | RemoteMessage::Close
            | RemoteMessage::Busy
            | RemoteMessage::UnknownClient
            | RemoteMessage::BadProtocol
            | RemoteMessage::IncompatibleVersion { .. }
            | RemoteMessage::ScreenSaver { .. }
            | RemoteMessage::MouseDown { .. }
            | RemoteMessage::MouseUp { .. }
            | RemoteMessage::MouseMove { .. }
            | RemoteMessage::MouseRelativeMove { .. }
            | RemoteMessage::DeviceInfo { .. }
            | RemoteMessage::KeyDown { .. }
            | RemoteMessage::KeyRepeat { .. }
            | RemoteMessage::KeyUp { .. } => false,
        }
    }

    const fn allows_terminal_control_decode(self, message: RemoteMessage) -> bool {
        match message {
            RemoteMessage::Close | RemoteMessage::BadProtocol => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::ClientHandshake | RemoteMessageState::Active
                )
            ),
            RemoteMessage::Busy | RemoteMessage::UnknownClient => matches!(
                (self.direction, self.state),
                (
                    RemoteMessageDirection::ServerToClient,
                    RemoteMessageState::ClientHandshake
                )
            ),
            RemoteMessage::Noop
            | RemoteMessage::KeepAlive
            | RemoteMessage::QueryInfo
            | RemoteMessage::InfoAck
            | RemoteMessage::ResetOptions
            | RemoteMessage::Leave
            | RemoteMessage::IncompatibleVersion { .. }
            | RemoteMessage::ScreenSaver { .. }
            | RemoteMessage::MouseDown { .. }
            | RemoteMessage::MouseUp { .. }
            | RemoteMessage::MouseMove { .. }
            | RemoteMessage::MouseRelativeMove { .. }
            | RemoteMessage::DeviceInfo { .. }
            | RemoteMessage::KeyDown { .. }
            | RemoteMessage::KeyRepeat { .. }
            | RemoteMessage::KeyUp { .. } => false,
        }
    }

    const fn allows_terminal_control_encode(self, message: RemoteMessage) -> bool {
        matches!(
            (message, self.direction, self.state),
            (
                RemoteMessage::BadProtocol,
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::ClientHandshake
            )
        )
    }

    const fn allows_incompatible_version(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::ClientHandshake
            )
        )
    }

    const fn allows_screen_saver(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_mouse_button(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_mouse_move(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_mouse_relative_move(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_device_info(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::ServerAwaitingInfo
            )
        )
    }

    const fn allows_key_down(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_key_repeat(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }

    const fn allows_key_up(self) -> bool {
        matches!(
            (self.direction, self.state),
            (
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active
            )
        )
    }
}

/// Decoded payload-only remote protocol message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMessage {
    /// The legacy `CNOP` no-operation command.
    Noop,
    /// The legacy `CALV` keep-alive command. Parsing it has no timer side effect.
    KeepAlive,
    /// The legacy `QINF` screen-information query.
    QueryInfo,
    /// The legacy `CIAK` screen-information acknowledgment.
    InfoAck,
    /// The legacy `CROP` reset-options command.
    ResetOptions,
    /// The legacy `COUT` leave-screen command.
    Leave,
    /// The legacy `CBYE` close-connection command.
    Close,
    /// The legacy `EBSY` client-name-busy rejection.
    Busy,
    /// The legacy `EUNK` unknown-client rejection.
    UnknownClient,
    /// The legacy `EBAD` bad-protocol error.
    BadProtocol,
    /// The legacy `EICV` incompatible-version rejection.
    IncompatibleVersion {
        /// Protocol major version advertised by the primary/server.
        major: i16,
        /// Protocol minor version advertised by the primary/server.
        minor: i16,
    },
    /// The legacy `CSEC` screen-saver state notification.
    ///
    /// The C++ receiver treats zero as inactive and every other wire value as active.
    ScreenSaver {
        /// Unnormalized one-byte wire value.
        raw: u8,
    },
    /// The legacy `DMDN` mouse-button press command.
    MouseDown {
        /// Unnormalized one-byte `ButtonID` wire value.
        button: u8,
    },
    /// The legacy `DMUP` mouse-button release command.
    MouseUp {
        /// Unnormalized one-byte `ButtonID` wire value.
        button: u8,
    },
    /// The legacy `DMMV` absolute mouse-move command.
    MouseMove {
        /// Signed 16-bit absolute X coordinate on the wire.
        x: i16,
        /// Signed 16-bit absolute Y coordinate on the wire.
        y: i16,
    },
    /// The legacy `DMRM` relative mouse-move command.
    MouseRelativeMove {
        /// Signed 16-bit horizontal motion delta on the wire.
        dx: i16,
        /// Signed 16-bit vertical motion delta on the wire.
        dy: i16,
    },
    /// The legacy `DINF` client display geometry and cursor-position message.
    DeviceInfo {
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        dummy: i16,
        mouse_x: i16,
        mouse_y: i16,
    },
    /// The legacy `DKDN` key-press command.
    KeyDown {
        /// Raw 16-bit `KeyID` field carried by the 1.6 wire format.
        key_id: u16,
        /// Raw 16-bit `KeyModifierMask` field carried by the 1.6 wire format.
        modifier_mask: u16,
        /// Raw 16-bit physical `KeyButton` field.
        button: u16,
    },
    /// The legacy `DKRP` key-auto-repeat command.
    KeyRepeat {
        /// Raw 16-bit `KeyID` field carried by the 1.6 wire format.
        key_id: u16,
        /// Raw 16-bit `KeyModifierMask` field carried by the 1.6 wire format.
        modifier_mask: u16,
        /// Low 16 bits of the sender's repeat count carried on the wire.
        count: u16,
        /// Raw 16-bit physical `KeyButton` field.
        button: u16,
    },
    /// The legacy `DKUP` key-release command.
    KeyUp {
        /// Raw 16-bit `KeyID` field carried by the 1.6 wire format.
        key_id: u16,
        /// Raw 16-bit `KeyModifierMask` field carried by the 1.6 wire format.
        modifier_mask: u16,
        /// Raw 16-bit physical `KeyButton` field.
        button: u16,
    },
}

impl RemoteMessage {
    /// Returns caller policy metadata indicating that processing should stop after this message.
    ///
    /// This does not execute a disconnect or protocol-state transition and does not alter parsing.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Close
                | Self::Busy
                | Self::UnknownClient
                | Self::BadProtocol
                | Self::IncompatibleVersion { .. }
        )
    }
}

/// Failure to encode a remote message in the requested protocol context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEncodeError {
    /// The message is not legal for the requested wire direction and receiver state.
    InvalidContext,
    /// The legacy fixed-width API cannot return a fielded payload.
    RequiresOutputBuffer,
    /// The message fields are structurally valid but are not emitted by the product.
    UnsupportedValue,
}

/// Failure to encode into a caller-provided output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEncodeToError {
    /// Message or context validation failed before output was touched.
    Encode(RemoteEncodeError),
    /// The validated message requires a larger output buffer.
    OutputTooSmall {
        /// Exact number of bytes required for this message.
        required: usize,
        /// Number of bytes supplied by the caller.
        available: usize,
    },
}

/// Result of parsing one message from a complete outer-frame payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteMessageParseResult {
    /// Message classification for the explicit wire direction and receiver state.
    pub category: Category,
    /// Exact message boundary, preserving any following payload bytes for the caller.
    pub consumed: Option<usize>,
    /// Decoded message, present only for [`Category::Accepted`].
    pub message: Option<RemoteMessage>,
}

impl RemoteMessageParseResult {
    const fn rejected(category: Category) -> Self {
        Self {
            category,
            consumed: None,
            message: None,
        }
    }
}

/// Result of parsing only the first u32-framed payload in a byte stream.
///
/// The variants intentionally prevent callers from treating the four inspected
/// bytes of an oversized prefix as a safe frame boundary. [`Self::Oversized`]
/// is terminal for the transport and must not be used for resynchronization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameParseResult<'a> {
    /// One complete non-empty frame was decoded.
    Accepted {
        /// Exact boundary of the first complete outer frame.
        consumed: usize,
        /// Complete payload borrowed from the input stream.
        payload: &'a [u8],
    },
    /// More stream bytes are required to complete the prefix or declared body.
    NeedMore,
    /// The C++ oracle consumed an empty prefix without producing a ready frame or error.
    SkippedEmpty {
        /// Progress made by consuming the zero-length prefix.
        consumed: usize,
    },
    /// The declared payload exceeds 4 MiB; the transport must be closed.
    Oversized,
}

/// Result of parsing one handshake from an already framed payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeParseResult<'a> {
    /// Handshake classification for the explicitly expected direction/state.
    pub category: Category,
    /// Internal handshake boundary for accepted or unsupported complete greetings.
    pub consumed: Option<usize>,
    /// Decoded handshake, present only for [`Category::Accepted`].
    pub handshake: Option<Handshake<'a>>,
}

impl HandshakeParseResult<'_> {
    const fn rejected(category: Category) -> Self {
        Self {
            category,
            consumed: None,
            handshake: None,
        }
    }

    const fn unsupported(consumed: usize) -> Self {
        Self {
            category: Category::UnsupportedVersion,
            consumed: Some(consumed),
            handshake: None,
        }
    }
}

/// Client-side protocol state for the incremental legacy stream adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientSessionState {
    /// The next complete frame must contain the server `Barrier` greeting.
    #[default]
    AwaitingHello,
    /// The greeting was accepted and remote commands may be consumed.
    Active,
    /// A terminal or malformed input closed the session.
    Closed,
}

/// Event emitted by [`ClientSession::receive`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientSessionEvent {
    /// A zero-length frame was consumed without producing a protocol event.
    SkippedEmptyFrame,
    /// The server greeting was accepted.
    HandshakeAccepted { major: i16, minor: i16 },
    /// One remote command was decoded.
    Message(RemoteMessage),
    /// The session rejected input and is now closed.
    Closed(Category),
}

/// Result of one incremental client-session poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSessionPoll {
    /// Bytes consumed from the supplied stream on this call.
    pub consumed: usize,
    /// Poll classification when no event was emitted.
    pub category: Category,
    /// At most one event, preserving deterministic caller dispatch.
    pub event: Option<ClientSessionEvent>,
}

/// Server-side protocol state for the incremental legacy stream adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServerSessionState {
    /// The next complete frame must contain the client `Barrier` greeting.
    #[default]
    AwaitingHelloBack,
    /// The greeting was accepted and the server is waiting for the client's
    /// initial information/control response.
    AwaitingInfo,
    /// The session is established and client control messages may be consumed.
    Active,
    /// A terminal or malformed input closed the session.
    Closed,
}

/// Event emitted by [`ServerSession::receive`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerSessionEvent {
    /// A zero-length frame was consumed without producing a protocol event.
    SkippedEmptyFrame,
    /// The client greeting was accepted.
    HandshakeAccepted { major: i16, minor: i16 },
    /// One client control message was decoded.
    Message(RemoteMessage),
    /// The session rejected input and is now closed.
    Closed(Category),
}

/// Result of one incremental server-session poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerSessionPoll {
    /// Bytes consumed from the supplied stream on this call.
    pub consumed: usize,
    /// Poll classification when no event was emitted.
    pub category: Category,
    /// At most one event, preserving deterministic caller dispatch.
    pub event: Option<ServerSessionEvent>,
}

/// Small allocating adapter that binds framing, handshake, and message parsing.
///
/// The adapter never resynchronizes malformed or oversized input. Coalesced
/// payload bytes are retained for the next poll rather than discarded.
#[derive(Debug, Default)]
pub struct ClientSession {
    state: ClientSessionState,
    stream: Vec<u8>,
    pending_payload: Vec<u8>,
}

impl ClientSession {
    /// Creates a client session waiting for the server greeting.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current session state.
    #[must_use]
    pub const fn state(&self) -> ClientSessionState {
        self.state
    }

    /// Feeds stream bytes and emits at most one protocol event.
    pub fn receive(&mut self, bytes: &[u8]) -> ClientSessionPoll {
        let supplied = bytes.len();
        self.stream.extend_from_slice(bytes);
        if self.state == ClientSessionState::Closed {
            return ClientSessionPoll {
                consumed: 0,
                category: Category::Malformed,
                event: None,
            };
        }

        if self.pending_payload.is_empty() {
            match parse_remote_frame(&self.stream) {
                FrameParseResult::NeedMore => {
                    return ClientSessionPoll {
                        consumed: 0,
                        category: Category::NeedMore,
                        event: None,
                    };
                }
                FrameParseResult::Oversized => {
                    self.state = ClientSessionState::Closed;
                    self.stream.clear();
                    return ClientSessionPoll {
                        consumed: supplied,
                        category: Category::Oversized,
                        event: Some(ClientSessionEvent::Closed(Category::Oversized)),
                    };
                }
                FrameParseResult::SkippedEmpty { consumed } => {
                    self.stream.drain(..consumed);
                    return ClientSessionPoll {
                        consumed,
                        category: Category::Accepted,
                        event: Some(ClientSessionEvent::SkippedEmptyFrame),
                    };
                }
                FrameParseResult::Accepted { consumed, payload } => {
                    let payload = payload.to_vec();
                    self.stream.drain(..consumed);
                    self.pending_payload.extend_from_slice(&payload);
                }
            }
        }

        if self.state == ClientSessionState::AwaitingHello {
            let result = parse_handshake(&self.pending_payload, ExpectedHandshake::Hello);
            match result.category {
                Category::Accepted => {
                    let handshake = result.handshake.expect("accepted handshake has value");
                    let (major, minor) = match handshake {
                        Handshake::Hello { major, minor } => (major, minor),
                        Handshake::HelloBack { .. } => {
                            unreachable!("hello parser returned hello-back")
                        }
                    };
                    let consumed = result.consumed.expect("accepted handshake has boundary");
                    self.pending_payload.drain(..consumed);
                    self.state = ClientSessionState::Active;
                    return ClientSessionPoll {
                        consumed: supplied,
                        category: Category::Accepted,
                        event: Some(ClientSessionEvent::HandshakeAccepted { major, minor }),
                    };
                }
                category => {
                    self.state = ClientSessionState::Closed;
                    self.pending_payload.clear();
                    return ClientSessionPoll {
                        consumed: supplied,
                        category,
                        event: Some(ClientSessionEvent::Closed(category)),
                    };
                }
            }
        }

        let result = parse_remote_message(
            &self.pending_payload,
            RemoteMessageContext::new(
                RemoteMessageDirection::ServerToClient,
                RemoteMessageState::Active,
            ),
        );
        match result.category {
            Category::Accepted => {
                let message = result.message.expect("accepted message has value");
                let consumed = result.consumed.expect("accepted message has boundary");
                self.pending_payload.drain(..consumed);
                if message.is_terminal() {
                    self.state = ClientSessionState::Closed;
                }
                ClientSessionPoll {
                    consumed: supplied,
                    category: Category::Accepted,
                    event: Some(ClientSessionEvent::Message(message)),
                }
            }
            category => {
                self.state = ClientSessionState::Closed;
                self.pending_payload.clear();
                ClientSessionPoll {
                    consumed: supplied,
                    category,
                    event: Some(ClientSessionEvent::Closed(category)),
                }
            }
        }
    }
}

/// Small allocating adapter for the server side of the legacy stream.
///
/// The adapter owns incomplete frames and never resynchronizes malformed or
/// oversized input. Socket ownership, TLS, and platform input dispatch remain
/// runtime concerns.
#[derive(Debug, Default)]
pub struct ServerSession {
    state: ServerSessionState,
    stream: Vec<u8>,
    pending_payload: Vec<u8>,
}

impl ServerSession {
    /// Creates a server session waiting for the client greeting.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current session state.
    #[must_use]
    pub const fn state(&self) -> ServerSessionState {
        self.state
    }

    /// Feeds stream bytes and emits at most one protocol event.
    pub fn receive(&mut self, bytes: &[u8]) -> ServerSessionPoll {
        let supplied = bytes.len();
        self.stream.extend_from_slice(bytes);
        if self.state == ServerSessionState::Closed {
            return ServerSessionPoll {
                consumed: 0,
                category: Category::Malformed,
                event: None,
            };
        }

        if self.pending_payload.is_empty() {
            match parse_remote_frame(&self.stream) {
                FrameParseResult::NeedMore => {
                    return ServerSessionPoll {
                        consumed: 0,
                        category: Category::NeedMore,
                        event: None,
                    };
                }
                FrameParseResult::Oversized => {
                    self.state = ServerSessionState::Closed;
                    self.stream.clear();
                    return ServerSessionPoll {
                        consumed: supplied,
                        category: Category::Oversized,
                        event: Some(ServerSessionEvent::Closed(Category::Oversized)),
                    };
                }
                FrameParseResult::SkippedEmpty { consumed } => {
                    self.stream.drain(..consumed);
                    return ServerSessionPoll {
                        consumed,
                        category: Category::Accepted,
                        event: Some(ServerSessionEvent::SkippedEmptyFrame),
                    };
                }
                FrameParseResult::Accepted { consumed, payload } => {
                    let payload = payload.to_vec();
                    self.stream.drain(..consumed);
                    self.pending_payload.extend_from_slice(&payload);
                }
            }
        }

        if self.state == ServerSessionState::AwaitingHelloBack {
            let result = parse_handshake(&self.pending_payload, ExpectedHandshake::HelloBack);
            match result.category {
                Category::Accepted => {
                    let handshake = result.handshake.expect("accepted handshake has value");
                    let (major, minor) = match handshake {
                        Handshake::HelloBack { major, minor, .. } => (major, minor),
                        Handshake::Hello { .. } => {
                            unreachable!("hello-back parser returned hello")
                        }
                    };
                    let consumed = result.consumed.expect("accepted handshake has boundary");
                    self.pending_payload.drain(..consumed);
                    self.state = ServerSessionState::AwaitingInfo;
                    return ServerSessionPoll {
                        consumed: supplied,
                        category: Category::Accepted,
                        event: Some(ServerSessionEvent::HandshakeAccepted { major, minor }),
                    };
                }
                category => {
                    self.state = ServerSessionState::Closed;
                    self.pending_payload.clear();
                    return ServerSessionPoll {
                        consumed: supplied,
                        category,
                        event: Some(ServerSessionEvent::Closed(category)),
                    };
                }
            }
        }

        let state = match self.state {
            ServerSessionState::AwaitingInfo => RemoteMessageState::ServerAwaitingInfo,
            ServerSessionState::Active => RemoteMessageState::Active,
            ServerSessionState::AwaitingHelloBack | ServerSessionState::Closed => {
                unreachable!("server state handled before message parsing")
            }
        };
        let result = parse_remote_message(
            &self.pending_payload,
            RemoteMessageContext::new(RemoteMessageDirection::ClientToServer, state),
        );
        match result.category {
            Category::Accepted => {
                let message = result.message.expect("accepted message has value");
                let consumed = result.consumed.expect("accepted message has boundary");
                self.pending_payload.drain(..consumed);
                if message.is_terminal() {
                    self.state = ServerSessionState::Closed;
                } else if matches!(message, RemoteMessage::DeviceInfo { .. }) {
                    self.state = ServerSessionState::Active;
                }
                ServerSessionPoll {
                    consumed: supplied,
                    category: Category::Accepted,
                    event: Some(ServerSessionEvent::Message(message)),
                }
            }
            category => {
                self.state = ServerSessionState::Closed;
                self.pending_payload.clear();
                ServerSessionPoll {
                    consumed: supplied,
                    category,
                    event: Some(ServerSessionEvent::Closed(category)),
                }
            }
        }
    }
}

/// Outcome of reading one borrowed u32-length-prefixed byte string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthPrefixedBytes<'a> {
    /// A complete field, borrowed directly from the source buffer.
    Complete(&'a [u8]),
    /// The length prefix or declared bytes are incomplete.
    NeedMore,
    /// The declared length exceeds the caller's limit.
    Oversized,
}

/// Non-allocating cursor over a borrowed byte slice.
#[derive(Clone, Copy, Debug)]
pub struct ByteCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ByteCursor<'a> {
    /// Creates a cursor positioned at the beginning of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Reads a big-endian u32-length-prefixed byte field without allocating.
    ///
    /// The cursor advances only when the complete field is available and within
    /// `maximum_length`. Remote lengths are checked before slicing.
    pub fn read_u32_length_prefixed(&mut self, maximum_length: usize) -> LengthPrefixedBytes<'a> {
        let Some(prefix_end) = self.position.checked_add(FRAME_PREFIX_LENGTH) else {
            return LengthPrefixedBytes::Oversized;
        };
        let Some(prefix) = self.bytes.get(self.position..prefix_end) else {
            return LengthPrefixedBytes::NeedMore;
        };
        let declared = usize::try_from(read_u32(prefix)).unwrap_or(usize::MAX);
        if declared > maximum_length {
            return LengthPrefixedBytes::Oversized;
        }
        let Some(field_end) = prefix_end.checked_add(declared) else {
            return LengthPrefixedBytes::Oversized;
        };
        let Some(field) = self.bytes.get(prefix_end..field_end) else {
            return LengthPrefixedBytes::NeedMore;
        };

        self.position = field_end;
        LengthPrefixedBytes::Complete(field)
    }
}

/// Parses only the first u32-framed payload in `stream`.
///
/// Payload semantics are intentionally not inspected. On acceptance, `payload`
/// borrows the complete declared payload and `consumed` marks exactly the first
/// outer-frame boundary, preserving any coalesced outer frames for the caller.
#[must_use]
pub fn parse_remote_frame(stream: &[u8]) -> FrameParseResult<'_> {
    let Some(prefix) = stream.get(..FRAME_PREFIX_LENGTH) else {
        return FrameParseResult::NeedMore;
    };
    let declared = usize::try_from(read_u32(prefix)).unwrap_or(usize::MAX);
    if declared > MAX_PAYLOAD_LENGTH {
        return FrameParseResult::Oversized;
    }
    if declared == 0 {
        return FrameParseResult::SkippedEmpty {
            consumed: FRAME_PREFIX_LENGTH,
        };
    }

    let Some(frame_length) = FRAME_PREFIX_LENGTH.checked_add(declared) else {
        return FrameParseResult::Oversized;
    };
    let Some(payload) = stream.get(FRAME_PREFIX_LENGTH..frame_length) else {
        return FrameParseResult::NeedMore;
    };

    FrameParseResult::Accepted {
        consumed: frame_length,
        payload,
    }
}

/// Encodes a payload-only remote message without allocating.
///
/// The returned bytes have static storage and do not include outer framing.
/// The explicit context is validated before any bytes are returned.
pub fn encode_remote_message(
    message: RemoteMessage,
    context: RemoteMessageContext,
) -> Result<&'static [u8; REMOTE_MESSAGE_CODE_LENGTH], RemoteEncodeError> {
    match message {
        RemoteMessage::Noop if context.allows_noop_encode() => Ok(REMOTE_NOOP_CODE),
        RemoteMessage::Noop => Err(RemoteEncodeError::InvalidContext),
        RemoteMessage::KeepAlive if context.allows_keep_alive_encode() => {
            Ok(REMOTE_KEEP_ALIVE_CODE)
        }
        RemoteMessage::KeepAlive => Err(RemoteEncodeError::InvalidContext),
        RemoteMessage::QueryInfo if context.allows_fixed_control_encode(message) => {
            Ok(REMOTE_QUERY_INFO_CODE)
        }
        RemoteMessage::InfoAck if context.allows_fixed_control_encode(message) => {
            Ok(REMOTE_INFO_ACK_CODE)
        }
        RemoteMessage::ResetOptions if context.allows_fixed_control_encode(message) => {
            Ok(REMOTE_RESET_OPTIONS_CODE)
        }
        RemoteMessage::Leave if context.allows_fixed_control_encode(message) => {
            Ok(REMOTE_LEAVE_CODE)
        }
        RemoteMessage::BadProtocol if context.allows_terminal_control_encode(message) => {
            Ok(REMOTE_BAD_PROTOCOL_CODE)
        }
        RemoteMessage::QueryInfo
        | RemoteMessage::InfoAck
        | RemoteMessage::ResetOptions
        | RemoteMessage::Leave
        | RemoteMessage::Close
        | RemoteMessage::Busy
        | RemoteMessage::UnknownClient
        | RemoteMessage::BadProtocol => Err(RemoteEncodeError::InvalidContext),
        RemoteMessage::IncompatibleVersion { .. }
        | RemoteMessage::ScreenSaver { .. }
        | RemoteMessage::MouseDown { .. }
        | RemoteMessage::MouseUp { .. }
        | RemoteMessage::MouseMove { .. }
        | RemoteMessage::MouseRelativeMove { .. }
        | RemoteMessage::DeviceInfo { .. }
        | RemoteMessage::KeyDown { .. }
        | RemoteMessage::KeyRepeat { .. }
        | RemoteMessage::KeyUp { .. } => Err(RemoteEncodeError::RequiresOutputBuffer),
    }
}

/// Encodes one payload-only remote message into caller-provided storage without allocating.
///
/// All context, value, and capacity checks happen before any output byte is modified.
pub fn encode_remote_message_to(
    message: RemoteMessage,
    context: RemoteMessageContext,
    output: &mut [u8],
) -> Result<usize, RemoteEncodeToError> {
    if let RemoteMessage::IncompatibleVersion { major, minor } = message {
        if !context.allows_incompatible_version() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        if (major, minor) != (SUPPORTED_MAJOR_VERSION, SUPPORTED_MINOR_VERSION) {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::UnsupportedValue,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_INCOMPATIBLE_VERSION_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_INCOMPATIBLE_VERSION_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_INCOMPATIBLE_VERSION_CODE);
        destination[4..6].copy_from_slice(&major.to_be_bytes());
        destination[6..8].copy_from_slice(&minor.to_be_bytes());
        return Ok(REMOTE_INCOMPATIBLE_VERSION_LENGTH);
    }

    if let RemoteMessage::ScreenSaver { raw } = message {
        if !context.allows_screen_saver() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        if raw > 1 {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::UnsupportedValue,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_SCREEN_SAVER_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_SCREEN_SAVER_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_SCREEN_SAVER_CODE);
        destination[REMOTE_MESSAGE_CODE_LENGTH] = raw;
        return Ok(REMOTE_SCREEN_SAVER_LENGTH);
    }

    if let RemoteMessage::MouseMove { x, y } = message {
        if !context.allows_mouse_move() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_MOUSE_MOVE_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_MOUSE_MOVE_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_MOUSE_MOVE_CODE);
        destination[4..6].copy_from_slice(&x.to_be_bytes());
        destination[6..8].copy_from_slice(&y.to_be_bytes());
        return Ok(REMOTE_MOUSE_MOVE_LENGTH);
    }

    if let RemoteMessage::DeviceInfo {
        x,
        y,
        width,
        height,
        dummy,
        mouse_x,
        mouse_y,
    } = message
    {
        if !context.allows_device_info() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        if width <= 0 || height <= 0 {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::UnsupportedValue,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_DEVICE_INFO_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_DEVICE_INFO_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_DEVICE_INFO_CODE);
        for (offset, value) in [x, y, width, height, dummy, mouse_x, mouse_y]
            .into_iter()
            .enumerate()
        {
            let start = REMOTE_MESSAGE_CODE_LENGTH + (offset * 2);
            destination[start..start + 2].copy_from_slice(&value.to_be_bytes());
        }
        return Ok(REMOTE_DEVICE_INFO_LENGTH);
    }

    if let RemoteMessage::MouseRelativeMove { dx, dy } = message {
        if !context.allows_mouse_relative_move() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_MOUSE_RELATIVE_MOVE_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_MOUSE_RELATIVE_MOVE_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_MOUSE_RELATIVE_MOVE_CODE);
        destination[4..6].copy_from_slice(&dx.to_be_bytes());
        destination[6..8].copy_from_slice(&dy.to_be_bytes());
        return Ok(REMOTE_MOUSE_RELATIVE_MOVE_LENGTH);
    }

    if let RemoteMessage::KeyDown {
        key_id,
        modifier_mask,
        button,
    } = message
    {
        if !context.allows_key_down() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_KEY_DOWN_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_KEY_DOWN_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_KEY_DOWN_CODE);
        destination[4..6].copy_from_slice(&key_id.to_be_bytes());
        destination[6..8].copy_from_slice(&modifier_mask.to_be_bytes());
        destination[8..10].copy_from_slice(&button.to_be_bytes());
        return Ok(REMOTE_KEY_DOWN_LENGTH);
    }

    if let RemoteMessage::KeyRepeat {
        key_id,
        modifier_mask,
        count,
        button,
    } = message
    {
        if !context.allows_key_repeat() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_KEY_REPEAT_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_KEY_REPEAT_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_KEY_REPEAT_CODE);
        destination[4..6].copy_from_slice(&key_id.to_be_bytes());
        destination[6..8].copy_from_slice(&modifier_mask.to_be_bytes());
        destination[8..10].copy_from_slice(&count.to_be_bytes());
        destination[10..12].copy_from_slice(&button.to_be_bytes());
        return Ok(REMOTE_KEY_REPEAT_LENGTH);
    }

    if let RemoteMessage::KeyUp {
        key_id,
        modifier_mask,
        button,
    } = message
    {
        if !context.allows_key_up() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_KEY_UP_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_KEY_UP_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_KEY_UP_CODE);
        destination[4..6].copy_from_slice(&key_id.to_be_bytes());
        destination[6..8].copy_from_slice(&modifier_mask.to_be_bytes());
        destination[8..10].copy_from_slice(&button.to_be_bytes());
        return Ok(REMOTE_KEY_UP_LENGTH);
    }

    if let RemoteMessage::MouseDown { button } = message {
        if !context.allows_mouse_button() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_MOUSE_BUTTON_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_MOUSE_BUTTON_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_MOUSE_DOWN_CODE);
        destination[REMOTE_MESSAGE_CODE_LENGTH] = button;
        return Ok(REMOTE_MOUSE_BUTTON_LENGTH);
    }

    if let RemoteMessage::MouseUp { button } = message {
        if !context.allows_mouse_button() {
            return Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::InvalidContext,
            ));
        }
        let available = output.len();
        let Some(destination) = output.get_mut(..REMOTE_MOUSE_BUTTON_LENGTH) else {
            return Err(RemoteEncodeToError::OutputTooSmall {
                required: REMOTE_MOUSE_BUTTON_LENGTH,
                available,
            });
        };
        destination[..REMOTE_MESSAGE_CODE_LENGTH].copy_from_slice(REMOTE_MOUSE_UP_CODE);
        destination[REMOTE_MESSAGE_CODE_LENGTH] = button;
        return Ok(REMOTE_MOUSE_BUTTON_LENGTH);
    }

    let encoded = encode_remote_message(message, context).map_err(RemoteEncodeToError::Encode)?;
    let available = output.len();
    let Some(destination) = output.get_mut(..REMOTE_MESSAGE_CODE_LENGTH) else {
        return Err(RemoteEncodeToError::OutputTooSmall {
            required: REMOTE_MESSAGE_CODE_LENGTH,
            available,
        });
    };
    destination.copy_from_slice(encoded);
    Ok(REMOTE_MESSAGE_CODE_LENGTH)
}

/// Parses one payload-only command using an explicit wire direction and receiver state.
///
/// On acceptance, `consumed` marks only the command boundary so trailing bytes
/// remain available to the caller. Outer framing is handled separately by
/// [`parse_remote_frame`].
#[must_use]
pub fn parse_remote_message(
    payload: &[u8],
    context: RemoteMessageContext,
) -> RemoteMessageParseResult {
    let Some(code) = payload.get(..REMOTE_MESSAGE_CODE_LENGTH) else {
        return RemoteMessageParseResult::rejected(Category::Malformed);
    };
    let (message, consumed) = if code == REMOTE_KEY_DOWN_CODE {
        if !context.allows_key_down() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) = payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_KEY_DOWN_LENGTH) else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::KeyDown {
                key_id: read_u16(&fields[..2]),
                modifier_mask: read_u16(&fields[2..4]),
                button: read_u16(&fields[4..]),
            },
            REMOTE_KEY_DOWN_LENGTH,
        )
    } else if code == REMOTE_KEY_REPEAT_CODE {
        if !context.allows_key_repeat() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) = payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_KEY_REPEAT_LENGTH) else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::KeyRepeat {
                key_id: read_u16(&fields[..2]),
                modifier_mask: read_u16(&fields[2..4]),
                count: read_u16(&fields[4..6]),
                button: read_u16(&fields[6..]),
            },
            REMOTE_KEY_REPEAT_LENGTH,
        )
    } else if code == REMOTE_KEY_UP_CODE {
        if !context.allows_key_up() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) = payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_KEY_UP_LENGTH) else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::KeyUp {
                key_id: read_u16(&fields[..2]),
                modifier_mask: read_u16(&fields[2..4]),
                button: read_u16(&fields[4..]),
            },
            REMOTE_KEY_UP_LENGTH,
        )
    } else if code == REMOTE_MOUSE_DOWN_CODE {
        if !context.allows_mouse_button() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(button) = payload.get(REMOTE_MESSAGE_CODE_LENGTH).copied() else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::MouseDown { button },
            REMOTE_MOUSE_BUTTON_LENGTH,
        )
    } else if code == REMOTE_MOUSE_UP_CODE {
        if !context.allows_mouse_button() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(button) = payload.get(REMOTE_MESSAGE_CODE_LENGTH).copied() else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::MouseUp { button },
            REMOTE_MOUSE_BUTTON_LENGTH,
        )
    } else if code == REMOTE_MOUSE_MOVE_CODE {
        if !context.allows_mouse_move() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) = payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_MOUSE_MOVE_LENGTH) else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::MouseMove {
                x: read_i16(&fields[..2]),
                y: read_i16(&fields[2..]),
            },
            REMOTE_MOUSE_MOVE_LENGTH,
        )
    } else if code == REMOTE_MOUSE_RELATIVE_MOVE_CODE {
        if !context.allows_mouse_relative_move() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) =
            payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_MOUSE_RELATIVE_MOVE_LENGTH)
        else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::MouseRelativeMove {
                dx: read_i16(&fields[..2]),
                dy: read_i16(&fields[2..]),
            },
            REMOTE_MOUSE_RELATIVE_MOVE_LENGTH,
        )
    } else if code == REMOTE_DEVICE_INFO_CODE {
        if !context.allows_device_info() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) = payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_DEVICE_INFO_LENGTH)
        else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        let width = read_i16(&fields[4..6]);
        let height = read_i16(&fields[6..8]);
        if width <= 0 || height <= 0 {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        (
            RemoteMessage::DeviceInfo {
                x: read_i16(&fields[..2]),
                y: read_i16(&fields[2..4]),
                width,
                height,
                dummy: read_i16(&fields[8..10]),
                mouse_x: read_i16(&fields[10..12]),
                mouse_y: read_i16(&fields[12..14]),
            },
            REMOTE_DEVICE_INFO_LENGTH,
        )
    } else if code == REMOTE_SCREEN_SAVER_CODE {
        if !context.allows_screen_saver() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(raw) = payload.get(REMOTE_MESSAGE_CODE_LENGTH).copied() else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::ScreenSaver { raw },
            REMOTE_SCREEN_SAVER_LENGTH,
        )
    } else if code == REMOTE_INCOMPATIBLE_VERSION_CODE {
        if !context.allows_incompatible_version() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        let Some(fields) =
            payload.get(REMOTE_MESSAGE_CODE_LENGTH..REMOTE_INCOMPATIBLE_VERSION_LENGTH)
        else {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        };
        (
            RemoteMessage::IncompatibleVersion {
                major: read_i16(&fields[..2]),
                minor: read_i16(&fields[2..]),
            },
            REMOTE_INCOMPATIBLE_VERSION_LENGTH,
        )
    } else if code == REMOTE_NOOP_CODE {
        if !context.allows_noop_decode() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        (RemoteMessage::Noop, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_KEEP_ALIVE_CODE {
        if !context.allows_keep_alive_decode() {
            return RemoteMessageParseResult::rejected(Category::Malformed);
        }
        (RemoteMessage::KeepAlive, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_QUERY_INFO_CODE {
        (RemoteMessage::QueryInfo, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_INFO_ACK_CODE {
        (RemoteMessage::InfoAck, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_RESET_OPTIONS_CODE {
        (RemoteMessage::ResetOptions, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_LEAVE_CODE {
        (RemoteMessage::Leave, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_CLOSE_CODE {
        (RemoteMessage::Close, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_BUSY_CODE {
        (RemoteMessage::Busy, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_UNKNOWN_CLIENT_CODE {
        (RemoteMessage::UnknownClient, REMOTE_MESSAGE_CODE_LENGTH)
    } else if code == REMOTE_BAD_PROTOCOL_CODE {
        (RemoteMessage::BadProtocol, REMOTE_MESSAGE_CODE_LENGTH)
    } else {
        return RemoteMessageParseResult::rejected(Category::Malformed);
    };
    if message != RemoteMessage::Noop
        && message != RemoteMessage::KeepAlive
        && !matches!(message, RemoteMessage::IncompatibleVersion { .. })
        && !matches!(message, RemoteMessage::ScreenSaver { .. })
        && !matches!(message, RemoteMessage::MouseDown { .. })
        && !matches!(message, RemoteMessage::MouseUp { .. })
        && !matches!(message, RemoteMessage::MouseMove { .. })
        && !matches!(message, RemoteMessage::MouseRelativeMove { .. })
        && !matches!(message, RemoteMessage::DeviceInfo { .. })
        && !matches!(message, RemoteMessage::KeyDown { .. })
        && !matches!(message, RemoteMessage::KeyRepeat { .. })
        && !matches!(message, RemoteMessage::KeyUp { .. })
        && !context.allows_fixed_control_decode(message)
        && !context.allows_terminal_control_decode(message)
    {
        return RemoteMessageParseResult::rejected(Category::Malformed);
    }

    RemoteMessageParseResult {
        category: Category::Accepted,
        consumed: Some(consumed),
        message: Some(message),
    }
}

/// Parses a handshake for the caller's explicit protocol direction/state.
///
/// The returned `consumed` boundary covers only the greeting, not trailing bytes
/// in the payload. This lets the caller continue parsing complete commands that
/// were coalesced into the same outer payload.
#[must_use]
pub fn parse_handshake(payload: &[u8], expected: ExpectedHandshake) -> HandshakeParseResult<'_> {
    let Some(version_bytes) = payload.get(HANDSHAKE_CODE.len()..HELLO_LENGTH) else {
        return HandshakeParseResult::rejected(Category::Malformed);
    };
    if !payload.starts_with(HANDSHAKE_CODE) {
        return HandshakeParseResult::rejected(Category::Malformed);
    }

    let major = read_i16(&version_bytes[..2]);
    let minor = read_i16(&version_bytes[2..]);

    match expected {
        ExpectedHandshake::Hello => parse_hello(major, minor),
        ExpectedHandshake::HelloBack => parse_hello_back(payload, major, minor),
    }
}

fn parse_hello(major: i16, minor: i16) -> HandshakeParseResult<'static> {
    let supported = major > SUPPORTED_MAJOR_VERSION
        || (major == SUPPORTED_MAJOR_VERSION && minor >= SUPPORTED_MINOR_VERSION);
    if !supported {
        return HandshakeParseResult::unsupported(HELLO_LENGTH);
    }

    HandshakeParseResult {
        category: Category::Accepted,
        consumed: Some(HELLO_LENGTH),
        handshake: Some(Handshake::Hello { major, minor }),
    }
}

fn parse_hello_back(payload: &[u8], major: i16, minor: i16) -> HandshakeParseResult<'_> {
    // ClientProxyUnknown rejects the complete unread hello-back payload before
    // parsing fields, so trailing commands count toward this consumer limit.
    if payload.len() > MAX_HELLO_BACK_LENGTH {
        return HandshakeParseResult::rejected(Category::Malformed);
    }
    let mut cursor = ByteCursor::new(&payload[HELLO_LENGTH..]);
    let client_name = match cursor.read_u32_length_prefixed(MAX_STRING_LENGTH) {
        LengthPrefixedBytes::Complete(client_name) => client_name,
        LengthPrefixedBytes::NeedMore => {
            return HandshakeParseResult::rejected(Category::Malformed);
        }
        LengthPrefixedBytes::Oversized => {
            return HandshakeParseResult::rejected(Category::Oversized);
        }
    };
    let Some(consumed) = HELLO_LENGTH.checked_add(cursor.position()) else {
        return HandshakeParseResult::rejected(Category::Oversized);
    };
    if consumed > MAX_HELLO_BACK_LENGTH {
        return HandshakeParseResult::rejected(Category::Malformed);
    }
    if (major, minor) != (SUPPORTED_MAJOR_VERSION, SUPPORTED_MINOR_VERSION) {
        return HandshakeParseResult::unsupported(consumed);
    }

    HandshakeParseResult {
        category: Category::Accepted,
        consumed: Some(consumed),
        handshake: Some(Handshake::HelloBack {
            major,
            minor,
            client_name,
        }),
    }
}

fn read_i16(bytes: &[u8]) -> i16 {
    i16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
