#![forbid(unsafe_code)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(unix)]
use std::thread::sleep;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use inputleap_protocol_legacy::{RemoteMessage, RemoteMessageContext, encode_remote_message_to};
#[cfg(unix)]
use inputleap_protocol_legacy::{RemoteMessageDirection, RemoteMessageState};
use inputleap_runtime::{SecureClientConnection, load_pem_certificates, load_pem_private_key};

#[cfg(unix)]
use inputleap_platform_x11::{InputEvent, X11Backend};

struct Config {
    address: SocketAddr,
    name: String,
    server_certificate: PathBuf,
    client_identity: PathBuf,
    duration: Option<Duration>,
}

fn next(args: &mut impl Iterator<Item = String>, option: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {option}"),
        )
    })
}

fn parse_duration(value: &str) -> io::Result<Duration> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "duration must be seconds"))?;
    Ok(Duration::from_secs(seconds))
}

fn parse_args() -> io::Result<Config> {
    let mut address = None;
    let mut name = None;
    let mut server_certificate = None;
    let mut client_identity = None;
    let mut duration = None;
    let mut args = env::args().skip(1);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--address" => {
                address =
                    Some(next(&mut args, "--address")?.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid address")
                    })?)
            }
            "--name" => name = Some(next(&mut args, "--name")?),
            "--server-certificate" => {
                server_certificate = Some(PathBuf::from(next(&mut args, "--server-certificate")?))
            }
            "--client-identity" => {
                client_identity = Some(PathBuf::from(next(&mut args, "--client-identity")?))
            }
            "--duration-secs" => {
                duration = Some(parse_duration(&next(&mut args, "--duration-secs")?)?)
            }
            "--help" | "-h" => {
                println!(
                    "usage: input-leap-agent --address IP:24800 --name linux-client --server-certificate PEM --client-identity PEM [--duration-secs N]"
                );
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option {option}"),
                ));
            }
        }
    }
    Ok(Config {
        address: address
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--address is required"))?,
        name: name
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--name is required"))?,
        server_certificate: server_certificate.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--server-certificate is required",
            )
        })?,
        client_identity: client_identity.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "--client-identity is required")
        })?,
        duration,
    })
}

fn frame(message: RemoteMessage, context: RemoteMessageContext) -> io::Result<Vec<u8>> {
    let mut payload = [0u8; 32];
    let length = encode_remote_message_to(message, context, &mut payload).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("encode failed: {error:?}"),
        )
    })?;
    let mut output = Vec::with_capacity(length + 4);
    output.extend_from_slice(&(length as u32).to_be_bytes());
    output.extend_from_slice(&payload[..length]);
    Ok(output)
}

fn hello_back(name: &str) -> io::Result<Vec<u8>> {
    let bytes = name.as_bytes();
    let payload_len = 15usize
        .checked_add(bytes.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
    let mut output = Vec::with_capacity(payload_len + 4);
    output.extend_from_slice(&(payload_len as u32).to_be_bytes());
    output.extend_from_slice(b"Barrier");
    output.extend_from_slice(&1i16.to_be_bytes());
    output.extend_from_slice(&6i16.to_be_bytes());
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(output)
}

#[cfg(unix)]
fn dispatch(backend: &X11Backend, message: RemoteMessage) -> Result<(), String> {
    match message {
        RemoteMessage::MouseMove { x, y } => {
            backend.move_pointer(inputleap_platform_x11::PointerPosition { x, y })
        }
        RemoteMessage::MouseRelativeMove { dx, dy } => backend.move_pointer_relative(dx, dy),
        RemoteMessage::MouseDown { button } => backend.send_button(true, button),
        RemoteMessage::MouseUp { button } => backend.send_button(false, button),
        RemoteMessage::KeyDown { button, .. } => backend.send_key(true, button as u8),
        RemoteMessage::KeyRepeat { button, .. } => backend.send_key(true, button as u8),
        RemoteMessage::KeyUp { button, .. } => backend.send_key(false, button as u8),
        RemoteMessage::Leave | RemoteMessage::KeepAlive | RemoteMessage::Noop => Ok(()),
        _ => Ok(()),
    }
    .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn capture_to_message(event: InputEvent) -> Option<RemoteMessage> {
    match event {
        InputEvent::KeyPress { keycode } => Some(RemoteMessage::KeyDown {
            key_id: keycode as u16,
            modifier_mask: 0,
            button: keycode as u16,
        }),
        InputEvent::KeyRelease { keycode } => Some(RemoteMessage::KeyUp {
            key_id: keycode as u16,
            modifier_mask: 0,
            button: keycode as u16,
        }),
        InputEvent::ButtonPress { button } => Some(RemoteMessage::MouseDown { button }),
        InputEvent::ButtonRelease { button } => Some(RemoteMessage::MouseUp { button }),
        InputEvent::Motion { position } => Some(RemoteMessage::MouseMove {
            x: position.x,
            y: position.y,
        }),
        InputEvent::MotionDelta { dx, dy } => Some(RemoteMessage::MouseRelativeMove { dx, dy }),
    }
}

#[cfg(unix)]
fn connect(
    config: &Config,
    device_info: RemoteMessage,
    info_context: RemoteMessageContext,
) -> Result<SecureClientConnection, String> {
    let mut server_certs =
        load_pem_certificates(&config.server_certificate).map_err(|error| error.to_string())?;
    let server_certificate = server_certs
        .drain(..)
        .next()
        .ok_or_else(|| "server certificate PEM is empty".to_string())?;
    let client_certs =
        load_pem_certificates(&config.client_identity).map_err(|error| error.to_string())?;
    let client_key =
        load_pem_private_key(&config.client_identity).map_err(|error| error.to_string())?;
    let mut connection = SecureClientConnection::connect_with_pinned_certificate_and_client_auth(
        config.address,
        Duration::from_secs(5),
        server_certificate,
        client_certs,
        client_key,
    )
    .map_err(|error| error.to_string())?;
    let handshake = connection.poll().map_err(|error| error.to_string())?;
    if !matches!(
        handshake.event,
        Some(
            inputleap_protocol_legacy::ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 }
        )
    ) {
        return Err(format!("unexpected greeting: {:?}", handshake.event));
    }
    connection
        .send(&hello_back(&config.name).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    connection
        .send(&frame(device_info, info_context).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    connection
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

#[cfg(unix)]
fn run(config: &Config) -> Result<(), String> {
    let backend = X11Backend::connect(None).map_err(|error| error.to_string())?;
    let capabilities = backend.capabilities();
    if !capabilities.xtest || !capabilities.xinput2 {
        return Err("XTEST and XInput2 are required".to_string());
    }
    backend.select_input().map_err(|error| error.to_string())?;
    let deadline = config.duration.map(|duration| Instant::now() + duration);
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    );
    let info_context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::ServerAwaitingInfo,
    );
    let (width, height, mouse_x, mouse_y) =
        backend.device_info().map_err(|error| error.to_string())?;
    loop {
        if deadline.is_some_and(|value| Instant::now() >= value) {
            return Ok(());
        }
        let mut connection = match connect(
            config,
            RemoteMessage::DeviceInfo {
                x: 0,
                y: 0,
                width,
                height,
                dummy: 0,
                mouse_x,
                mouse_y,
            },
            info_context,
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("connect failed: {error}");
                sleep(Duration::from_secs(1));
                continue;
            }
        };

        let mut keepalive = Instant::now();
        let mut remote_control_active = false;
        let mut session_failed = false;
        loop {
            if deadline.is_some_and(|value| Instant::now() >= value) {
                return Ok(());
            }
            loop {
                match connection.poll_nonblocking() {
                    Ok(Some(poll)) => {
                        if let Some(message) = poll.event {
                            match message {
                                inputleap_protocol_legacy::ClientSessionEvent::Message(message) => {
                                    if matches!(message, RemoteMessage::Leave) {
                                        remote_control_active = false;
                                    } else if matches!(
                                        message,
                                        RemoteMessage::MouseMove { .. }
                                            | RemoteMessage::MouseRelativeMove { .. }
                                            | RemoteMessage::MouseDown { .. }
                                            | RemoteMessage::MouseUp { .. }
                                            | RemoteMessage::KeyDown { .. }
                                            | RemoteMessage::KeyRepeat { .. }
                                            | RemoteMessage::KeyUp { .. }
                                    ) {
                                        remote_control_active = true;
                                        if let Err(error) = dispatch(&backend, message) {
                                            eprintln!("X11 dispatch failed: {error}");
                                            session_failed = true;
                                            break;
                                        }
                                    }
                                }
                                inputleap_protocol_legacy::ClientSessionEvent::Closed(category) => {
                                    eprintln!("peer closed: {category:?}");
                                    session_failed = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("receive failed: {error}");
                        session_failed = true;
                        break;
                    }
                }
            }
            if session_failed {
                break;
            }
            /*
             * The server's input frames are handled above.  Keep the
             * receive loop separate from capture so a transport failure
             * always reaches the reconnect path below.
             */
            if remote_control_active {
                loop {
                    let event = match backend.poll_event() {
                        Ok(Some(event)) => event,
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("X11 capture failed: {error}");
                            session_failed = true;
                            break;
                        }
                    };
                    if let Some(message) = capture_to_message(event) {
                        let encoded = match frame(message, context) {
                            Ok(frame) => frame,
                            Err(error) => {
                                eprintln!("event encode failed: {error}");
                                session_failed = true;
                                break;
                            }
                        };
                        if let Err(error) = connection.send(&encoded) {
                            eprintln!("event send failed: {error}");
                            session_failed = true;
                            break;
                        }
                    }
                }
            }
            if session_failed {
                break;
            }
            if keepalive.elapsed() >= Duration::from_secs(2) {
                let encoded =
                    frame(RemoteMessage::KeepAlive, context).map_err(|error| error.to_string())?;
                if let Err(error) = connection.send(&encoded) {
                    eprintln!("keepalive send failed: {error}");
                    break;
                }
                keepalive = Instant::now();
            }
            sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(not(unix))]
fn run(_config: &Config) -> Result<(), String> {
    Err("input-leap-agent requires Unix/X11".to_string())
}

fn main() {
    if env::args().any(|arg| arg == "--status") {
        println!(
            r#"{{"agent":"input-leap-agent-r3-bootstrap","version":"0.1.0-dev-r3","status":"READY","pid":null}}"#
        );
        return;
    }

    let result = match parse_args() {
        Ok(config) => run(&config),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = result {
        eprintln!("input-leap-agent: {error}");
        std::process::exit(1);
    }
}
