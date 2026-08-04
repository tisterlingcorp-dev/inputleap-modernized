use inputleap_protocol_legacy::{
    Category, REMOTE_MESSAGE_CODE_LENGTH, RemoteMessage, RemoteMessageContext,
    RemoteMessageDirection, RemoteMessageState, encode_remote_message, parse_remote_message,
};
use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

fn parse_message(value: &OsString) -> Result<RemoteMessage, String> {
    match value.to_str() {
        Some("QINF") => Ok(RemoteMessage::QueryInfo),
        Some("CIAK") => Ok(RemoteMessage::InfoAck),
        Some("CROP") => Ok(RemoteMessage::ResetOptions),
        Some("COUT") => Ok(RemoteMessage::Leave),
        _ => Err("message must be QINF, CIAK, CROP, or COUT".to_owned()),
    }
}

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
    let message_name = arguments.next().ok_or_else(usage)?;
    let message = parse_message(&message_name)?;
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    let direction = parse_direction(&arguments.next().ok_or_else(usage)?)?;
    let state = parse_state(&arguments.next().ok_or_else(usage)?)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let context = RemoteMessageContext::new(direction, state);
    match mode.to_str() {
        Some("decode") => {
            let mut input = File::open(&path)
                .map_err(|error| format!("unable to open {}: {error}", path.display()))?;
            let metadata = input
                .metadata()
                .map_err(|error| format!("unable to inspect {}: {error}", path.display()))?;
            let expected_length = u64::try_from(REMOTE_MESSAGE_CODE_LENGTH)
                .map_err(|_| "message-code length does not fit u64".to_owned())?;
            if metadata.len() != expected_length {
                return Err(format!(
                    "strict-file payload length {} does not match message-code length {expected_length}",
                    metadata.len()
                ));
            }

            let mut bytes = [0_u8; REMOTE_MESSAGE_CODE_LENGTH];
            input
                .read_exact(&mut bytes)
                .map_err(|error| format!("unable to read {}: {error}", path.display()))?;
            let mut trailing = [0_u8; 1];
            if input
                .read(&mut trailing)
                .map_err(|error| format!("unable to finish reading {}: {error}", path.display()))?
                != 0
            {
                return Err("strict-file payload grew beyond one message code".to_owned());
            }
            let parsed = parse_remote_message(&bytes, context);
            if parsed.category != Category::Accepted
                || parsed.message != Some(message)
                || parsed.consumed != Some(REMOTE_MESSAGE_CODE_LENGTH)
            {
                return Err(format!(
                    "payload was not exactly one accepted {message_name:?}: {parsed:?}"
                ));
            }
            println!(
                "FIXED_CONTROL_RUST_DECODE_PASS message={} consumed={} path={}",
                message_name.to_string_lossy(),
                REMOTE_MESSAGE_CODE_LENGTH,
                path.display()
            );
        }
        Some("encode") => {
            let bytes = encode_remote_message(message, context).map_err(|error| {
                format!(
                    "cannot encode {} in this context: {error:?}",
                    message_name.to_string_lossy()
                )
            })?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("unable to create {}: {error}", path.display()))?;
            output
                .write_all(bytes)
                .map_err(|error| format!("unable to write {}: {error}", path.display()))?;
            output
                .flush()
                .map_err(|error| format!("unable to flush {}: {error}", path.display()))?;
            println!(
                "FIXED_CONTROL_RUST_ENCODE_PASS message={} bytes={} path={}",
                message_name.to_string_lossy(),
                bytes.len(),
                path.display()
            );
        }
        _ => return Err(usage()),
    }

    Ok(())
}

fn usage() -> String {
    "usage: fixed_control_interop <decode|encode> <QINF|CIAK|CROP|COUT> <path> <client-to-server|server-to-client> <client-handshake|server-awaiting-hello-back|server-awaiting-info|active>".to_owned()
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fixed_control_interop: {error}");
        std::process::exit(1);
    }
}
