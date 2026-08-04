use inputleap_protocol_legacy::{
    Category, REMOTE_MESSAGE_CODE_LENGTH, RemoteMessage, RemoteMessageContext,
    RemoteMessageDirection, RemoteMessageState, encode_remote_message, parse_remote_message,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

fn parse_direction(value: &OsString) -> Result<RemoteMessageDirection, String> {
    match value.to_str() {
        Some("client-to-server") => Ok(RemoteMessageDirection::ClientToServer),
        Some("server-to-client") => Ok(RemoteMessageDirection::ServerToClient),
        _ => Err("direction must be client-to-server or server-to-client".to_owned()),
    }
}

fn parse_state(value: &OsString) -> Result<RemoteMessageState, String> {
    match value.to_str() {
        Some("client-handshake") => Ok(RemoteMessageState::ClientHandshake),
        Some("server-awaiting-hello-back") => Ok(RemoteMessageState::ServerAwaitingHelloBack),
        Some("server-awaiting-info") => Ok(RemoteMessageState::ServerAwaitingInfo),
        Some("active") => Ok(RemoteMessageState::Active),
        _ => Err(
            "state must be client-handshake, server-awaiting-hello-back, server-awaiting-info, or active"
                .to_owned(),
        ),
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let mode = arguments.next().ok_or_else(usage)?;
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    let direction = parse_direction(&arguments.next().ok_or_else(usage)?)?;
    let state = parse_state(&arguments.next().ok_or_else(usage)?)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let context = RemoteMessageContext::new(direction, state);
    match mode.to_str() {
        Some("decode") => {
            let metadata = fs::metadata(&path)
                .map_err(|error| format!("unable to inspect {}: {error}", path.display()))?;
            let expected_length = u64::try_from(REMOTE_MESSAGE_CODE_LENGTH)
                .map_err(|_| "expected message length does not fit u64".to_owned())?;
            if metadata.len() != expected_length {
                return Err(format!(
                    "payload length {} does not match expected length {expected_length}",
                    metadata.len()
                ));
            }
            let bytes = fs::read(&path)
                .map_err(|error| format!("unable to read {}: {error}", path.display()))?;
            let parsed = parse_remote_message(&bytes, context);
            if parsed.category != Category::Accepted
                || parsed.message != Some(RemoteMessage::Noop)
                || parsed.consumed != Some(bytes.len())
            {
                return Err(format!(
                    "payload was not exactly one accepted no-op: {parsed:?}"
                ));
            }
            println!(
                "CNOP_RUST_DECODE_PASS consumed={} path={}",
                bytes.len(),
                path.display()
            );
        }
        Some("encode") => {
            let bytes = encode_remote_message(RemoteMessage::Noop, context)
                .map_err(|error| format!("cannot encode no-op in this context: {error:?}"))?;
            fs::write(&path, bytes)
                .map_err(|error| format!("unable to write {}: {error}", path.display()))?;
            println!(
                "CNOP_RUST_ENCODE_PASS bytes={} path={}",
                bytes.len(),
                path.display()
            );
        }
        _ => return Err(usage()),
    }

    Ok(())
}

fn usage() -> String {
    "usage: cnop_interop <decode|encode> <path> <client-to-server|server-to-client> <client-handshake|server-awaiting-hello-back|server-awaiting-info|active>".to_owned()
}

fn main() {
    if let Err(error) = run() {
        eprintln!("cnop_interop: {error}");
        std::process::exit(1);
    }
}
