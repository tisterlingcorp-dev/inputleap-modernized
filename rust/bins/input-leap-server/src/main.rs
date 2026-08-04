#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use inputleap_platform_windows::{WindowsInputBackend, WindowsInputCapture};
use inputleap_protocol_legacy::{
    RemoteMessageContext, RemoteMessageDirection, RemoteMessageState, ServerSessionEvent,
    ServerSessionState, encode_remote_message_to,
};
use inputleap_runtime::{
    SecureServerListener, load_pem_certificates, load_pem_private_key, root_store_from_certificates,
};

const DEFAULT_BIND: &str = "0.0.0.0:24800";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Config {
    bind: SocketAddr,
    certificate: PathBuf,
    private_key_source: PathBuf,
    client_roots: PathBuf,
}

fn usage() -> &'static str {
    "usage: input-leap-server --certificate PEM --private-key-source PEM --client-roots PEM [--bind ADDR]"
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {option}; {}", usage()),
        )
    })
}

fn parse_args() -> io::Result<Config> {
    let mut bind = DEFAULT_BIND.parse().expect("valid default bind address");
    let mut certificate = None;
    let mut private_key_source = None;
    let mut client_roots = None;
    let mut args = env::args().skip(1);

    while let Some(option) = args.next() {
        match option.as_str() {
            "--bind" => {
                bind = next_value(&mut args, "--bind")?.parse().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid bind address: {error}"),
                    )
                })?;
            }
            "--certificate" => {
                certificate = Some(PathBuf::from(next_value(&mut args, "--certificate")?))
            }
            "--private-key-source" => {
                private_key_source = Some(PathBuf::from(next_value(
                    &mut args,
                    "--private-key-source",
                )?));
            }
            "--client-roots" => {
                client_roots = Some(PathBuf::from(next_value(&mut args, "--client-roots")?))
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option {option}; {}", usage()),
                ));
            }
        }
    }

    Ok(Config {
        bind,
        certificate: required_path(certificate, "--certificate")?,
        private_key_source: required_path(private_key_source, "--private-key-source")?,
        client_roots: required_path(client_roots, "--client-roots")?,
    })
}

fn required_path(value: Option<PathBuf>, option: &str) -> io::Result<PathBuf> {
    value.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option} is required; {}", usage()),
        )
    })
}

fn hello_frame() -> [u8; 15] {
    // Legacy server greeting: u32 payload length + Barrier + i16 major/minor.
    [
        0, 0, 0, 11, b'B', b'a', b'r', b'r', b'i', b'e', b'r', 0, 1, 0, 6,
    ]
}

fn validate_file(path: &Path, label: &str) -> io::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{label} does not exist or is not a file: {}",
                path.display()
            ),
        ))
    }
}

fn serve_connection(
    listener: &SecureServerListener,
    timeout: Duration,
    input_backend: &WindowsInputBackend,
) -> io::Result<()> {
    let mut connection = listener.accept(timeout)?;
    let mut input_capture = WindowsInputCapture::new();
    let mut remote_control_active = false;
    let mut peer_shape = None;
    connection.send(&hello_frame())?;
    connection.set_nonblocking(true)?;

    loop {
        if let Some(poll) = connection.poll_nonblocking()? {
            if let Some(event) = poll.event {
                println!("event={event:?}");
                if let ServerSessionEvent::Message(message) = event {
                    match message {
                        inputleap_protocol_legacy::RemoteMessage::DeviceInfo {
                            width,
                            height,
                            ..
                        } => {
                            remote_control_active = false;
                            peer_shape = (width > 0 && height > 0).then_some((width, height));
                        }
                        inputleap_protocol_legacy::RemoteMessage::Leave => {
                            remote_control_active = false;
                        }
                        _ => {}
                    }
                    if is_injectable_input(&message) {
                        match input_backend.inject(message) {
                            Ok(()) => {}
                            Err(error) => eprintln!("input dispatch rejected: {error:?}"),
                        }
                    }
                }
                if matches!(event, ServerSessionEvent::Closed(_)) {
                    return Ok(());
                }
            }
            if connection.session().state() == ServerSessionState::Closed {
                return Ok(());
            }
        }
        if connection.session().state() == ServerSessionState::Active {
            send_captured_input(
                &mut connection,
                &mut input_capture,
                &mut remote_control_active,
                peer_shape,
            )?;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn is_injectable_input(message: &inputleap_protocol_legacy::RemoteMessage) -> bool {
    matches!(
        message,
        inputleap_protocol_legacy::RemoteMessage::MouseDown { .. }
            | inputleap_protocol_legacy::RemoteMessage::MouseUp { .. }
            | inputleap_protocol_legacy::RemoteMessage::MouseMove { .. }
            | inputleap_protocol_legacy::RemoteMessage::MouseRelativeMove { .. }
            | inputleap_protocol_legacy::RemoteMessage::KeyDown { .. }
            | inputleap_protocol_legacy::RemoteMessage::KeyRepeat { .. }
            | inputleap_protocol_legacy::RemoteMessage::KeyUp { .. }
    )
}

#[cfg(windows)]
fn encode_input_frame(message: inputleap_protocol_legacy::RemoteMessage) -> io::Result<Vec<u8>> {
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::Active,
    );
    let mut payload = [0u8; 16];
    let payload_len = encode_remote_message_to(message, context, &mut payload)
        .map_err(|error| io::Error::other(format!("input encode failed: {error:?}")))?;
    let frame_len = u32::try_from(payload_len)
        .map_err(|_| io::Error::other("encoded input message is too large"))?;
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&frame_len.to_be_bytes());
    frame.extend_from_slice(&payload[..payload_len]);
    Ok(frame)
}

#[cfg(windows)]
fn send_captured_input(
    connection: &mut inputleap_runtime::SecureServerConnection,
    input_capture: &mut WindowsInputCapture,
    remote_control_active: &mut bool,
    peer_shape: Option<(i16, i16)>,
) -> io::Result<()> {
    let (screen_width, _) = input_capture
        .screen_size()
        .map_err(|error| io::Error::other(format!("Windows screen query failed: {error:?}")))?;
    let edge = screen_width.saturating_sub(2);
    for mut message in input_capture
        .poll()
        .map_err(|error| io::Error::other(format!("Windows input capture failed: {error:?}")))?
    {
        if let inputleap_protocol_legacy::RemoteMessage::MouseMove { x, .. } = message {
            if !*remote_control_active && x >= edge {
                *remote_control_active = true;
                message = map_mouse_move_for_peer(message, peer_shape, true);
            } else if *remote_control_active && x < edge {
                connection.send(&encode_input_frame(
                    inputleap_protocol_legacy::RemoteMessage::Leave,
                )?)?;
                *remote_control_active = false;
                continue;
            }
        }
        if !*remote_control_active {
            continue;
        }
        let frame = encode_input_frame(message)?;
        connection.send(&frame)?;
    }
    Ok(())
}

fn map_mouse_move_for_peer(
    message: inputleap_protocol_legacy::RemoteMessage,
    peer_shape: Option<(i16, i16)>,
    entering_from_right: bool,
) -> inputleap_protocol_legacy::RemoteMessage {
    let inputleap_protocol_legacy::RemoteMessage::MouseMove { x, y } = message else {
        return message;
    };
    let Some((width, height)) = peer_shape else {
        return message;
    };
    inputleap_protocol_legacy::RemoteMessage::MouseMove {
        x: if entering_from_right {
            0
        } else {
            x.clamp(0, width.saturating_sub(1))
        },
        y: y.clamp(0, height.saturating_sub(1)),
    }
}

#[cfg(not(windows))]
fn send_captured_input(
    _connection: &mut inputleap_runtime::SecureServerConnection,
    _input_capture: &mut WindowsInputCapture,
    _remote_control_active: &mut bool,
    _peer_shape: Option<(i16, i16)>,
) -> io::Result<()> {
    Ok(())
}

fn run(config: Config) -> io::Result<()> {
    validate_file(&config.certificate, "certificate")?;
    validate_file(&config.private_key_source, "private-key-source")?;
    validate_file(&config.client_roots, "client-roots")?;

    let certificates = load_pem_certificates(&config.certificate)?;
    let private_key = load_pem_private_key(&config.private_key_source)?;
    let client_root_certificates = load_pem_certificates(&config.client_roots)?;
    let client_roots = root_store_from_certificates(&client_root_certificates)?;
    let listener =
        SecureServerListener::bind(config.bind, certificates, private_key, client_roots)?;
    let input_backend = WindowsInputBackend::new();

    println!("input-leap-server listening on {}", listener.local_addr()?);
    loop {
        if let Err(error) = serve_connection(&listener, DEFAULT_TIMEOUT, &input_backend) {
            eprintln!("connection closed: {error}");
        }
    }
}

fn main() -> io::Result<()> {
    let config = parse_args()?;
    run(config)
}

#[cfg(test)]
mod tests {
    use super::{hello_frame, is_injectable_input};

    #[cfg(windows)]
    use super::encode_input_frame;
    use super::map_mouse_move_for_peer;
    use inputleap_protocol_legacy::RemoteMessage;

    #[test]
    fn control_messages_are_not_sent_to_input_backend() {
        assert!(!is_injectable_input(
            &inputleap_protocol_legacy::RemoteMessage::KeepAlive
        ));
        assert!(!is_injectable_input(
            &inputleap_protocol_legacy::RemoteMessage::DeviceInfo {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                dummy: 0,
                mouse_x: 1,
                mouse_y: 2,
            }
        ));
        assert!(!is_injectable_input(
            &inputleap_protocol_legacy::RemoteMessage::Leave
        ));
    }

    #[test]
    fn entering_right_edge_maps_to_peer_left_edge() {
        assert_eq!(
            map_mouse_move_for_peer(
                RemoteMessage::MouseMove { x: 1919, y: 1200 },
                Some((1280, 720)),
                true,
            ),
            RemoteMessage::MouseMove { x: 0, y: 719 }
        );
    }

    #[test]
    fn active_motion_is_clamped_to_peer_shape() {
        assert_eq!(
            map_mouse_move_for_peer(
                RemoteMessage::MouseMove { x: 1919, y: -20 },
                Some((1280, 720)),
                false,
            ),
            RemoteMessage::MouseMove { x: 1279, y: 0 }
        );
    }

    #[test]
    fn hello_frame_matches_legacy_wire_shape() {
        assert_eq!(&hello_frame()[..4], &[0, 0, 0, 11]);
        assert_eq!(&hello_frame()[4..], b"Barrier\0\x01\0\x06");
    }

    #[cfg(windows)]
    #[test]
    fn captured_input_frame_matches_legacy_wire_shape() {
        let frame = encode_input_frame(RemoteMessage::MouseRelativeMove { dx: -2, dy: 3 })
            .expect("active server-to-client input must encode");
        assert_eq!(&frame[..4], &[0, 0, 0, 8]);
        assert_eq!(&frame[4..8], b"DMRM");
        assert_eq!(&frame[8..10], &(-2i16).to_be_bytes());
        assert_eq!(&frame[10..12], &3i16.to_be_bytes());
    }
}
