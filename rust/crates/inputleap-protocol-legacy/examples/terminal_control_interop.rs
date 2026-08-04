use inputleap_protocol_legacy::{
    Category, REMOTE_MESSAGE_CODE_LENGTH, RemoteMessage, RemoteMessageContext,
    RemoteMessageDirection, RemoteMessageState, encode_remote_message, parse_remote_message,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn parse_message(value: &OsStr) -> Result<RemoteMessage, String> {
    match value.to_str() {
        Some("CBYE") => Ok(RemoteMessage::Close),
        Some("EBSY") => Ok(RemoteMessage::Busy),
        Some("EUNK") => Ok(RemoteMessage::UnknownClient),
        Some("EBAD") => Ok(RemoteMessage::BadProtocol),
        _ => Err("message must be CBYE, EBSY, EUNK, or EBAD".to_owned()),
    }
}

fn parse_direction(value: &OsStr) -> Result<RemoteMessageDirection, String> {
    match value.to_str() {
        Some("client-to-server") => Ok(RemoteMessageDirection::ClientToServer),
        Some("server-to-client") => Ok(RemoteMessageDirection::ServerToClient),
        _ => Err("direction must be client-to-server or server-to-client".to_owned()),
    }
}

fn parse_state(value: &OsStr) -> Result<RemoteMessageState, String> {
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

fn context(direction: &OsStr, state: &OsStr) -> Result<RemoteMessageContext, String> {
    Ok(RemoteMessageContext::new(
        parse_direction(direction)?,
        parse_state(state)?,
    ))
}

fn read_exact_message(path: &Path) -> Result<[u8; REMOTE_MESSAGE_CODE_LENGTH], String> {
    let mut input = File::open(path).map_err(|error| format!("unable to open input: {error}"))?;
    let mut bytes = [0_u8; REMOTE_MESSAGE_CODE_LENGTH];
    input
        .read_exact(&mut bytes)
        .map_err(|error| format!("unable to read exact four-byte payload: {error}"))?;
    let mut trailing = [0_u8; 1];
    let trailing_count = input
        .read(&mut trailing)
        .map_err(|error| format!("unable to verify input end-of-file: {error}"))?;
    if trailing_count != 0 {
        return Err("input contains trailing bytes".to_owned());
    }
    Ok(bytes)
}

fn decode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 6 {
        return Err("usage: terminal_control_interop decode <CBYE|EBSY|EUNK|EBAD> <path> <direction> <receiver-state>".to_owned());
    }
    let expected = parse_message(&args[2])?;
    let path = PathBuf::from(&args[3]);
    let message_context = context(&args[4], &args[5])?;
    let bytes = read_exact_message(&path)?;
    let parsed = parse_remote_message(&bytes, message_context);
    if parsed.category != Category::Accepted
        || parsed.consumed != Some(REMOTE_MESSAGE_CODE_LENGTH)
        || parsed.message != Some(expected)
    {
        return Err(format!(
            "payload was not accepted as {expected:?} in the requested context: {parsed:?}"
        ));
    }
    if !expected.is_terminal() {
        return Err("accepted selector is not classified as terminal policy metadata".to_owned());
    }
    println!(
        "RUST_TERMINAL_CONTROL_DECODE_PASS message={expected:?} consumed={} terminal_policy_metadata=true",
        REMOTE_MESSAGE_CODE_LENGTH
    );
    Ok(())
}

fn encode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 6 {
        return Err("usage: terminal_control_interop encode <CBYE|EBSY|EUNK|EBAD> <new-path> <direction> <receiver-state>".to_owned());
    }
    let message = parse_message(&args[2])?;
    let path = PathBuf::from(&args[3]);
    let message_context = context(&args[4], &args[5])?;
    let bytes = encode_remote_message(message, message_context)
        .map_err(|error| format!("encode rejected requested context: {error:?}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("unable to create output exclusively: {error}"))?;
    output
        .write_all(bytes)
        .map_err(|error| format!("unable to write output: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("unable to flush output: {error}"))?;
    println!(
        "RUST_TERMINAL_CONTROL_ENCODE_PASS message={message:?} bytes={} terminal_policy_metadata=true path={}",
        bytes.len(),
        path.display()
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<OsString> = env::args_os().collect();
    match args.get(1).and_then(|value| value.to_str()) {
        Some("decode") => decode(&args),
        Some("encode") => encode(&args),
        _ => Err("usage: terminal_control_interop <decode|encode> ...".to_owned()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("terminal_control_interop: {error}");
        std::process::exit(1);
    }
}
