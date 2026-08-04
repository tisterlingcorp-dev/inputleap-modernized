use inputleap_protocol_legacy::{
    Category, FrameParseResult, REMOTE_MESSAGE_CODE_LENGTH, RemoteMessage, RemoteMessageContext,
    RemoteMessageDirection, RemoteMessageState, encode_remote_message, parse_remote_frame,
    parse_remote_message,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const KEEP_ALIVE_FRAME_LENGTH: usize = 4 + REMOTE_MESSAGE_CODE_LENGTH;

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

fn read_exact_file<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let mut input = File::open(path).map_err(|error| format!("unable to open input: {error}"))?;
    let mut bytes = [0_u8; N];
    input
        .read_exact(&mut bytes)
        .map_err(|error| format!("unable to read exact {N}-byte input: {error}"))?;
    let mut trailing = [0_u8; 1];
    let count = input
        .read(&mut trailing)
        .map_err(|error| format!("unable to verify input end-of-file: {error}"))?;
    if count != 0 {
        return Err("input contains trailing bytes".to_owned());
    }
    Ok(bytes)
}

fn require_keep_alive(payload: &[u8], message_context: RemoteMessageContext) -> Result<(), String> {
    let parsed = parse_remote_message(payload, message_context);
    if parsed.category != Category::Accepted
        || parsed.consumed != Some(REMOTE_MESSAGE_CODE_LENGTH)
        || parsed.message != Some(RemoteMessage::KeepAlive)
    {
        return Err(format!(
            "payload was not accepted as KeepAlive in the requested context: {parsed:?}"
        ));
    }
    if RemoteMessage::KeepAlive.is_terminal() {
        return Err("KeepAlive must remain nonterminal parser metadata".to_owned());
    }
    Ok(())
}

fn decode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: keepalive_interop decode <path> <direction> <receiver-state>".to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<REMOTE_MESSAGE_CODE_LENGTH>(&path)?;
    require_keep_alive(&bytes, message_context)?;
    println!(
        "RUST_KEEPALIVE_DECODE_PASS consumed={} stateful_effects=NOT_EXECUTED",
        REMOTE_MESSAGE_CODE_LENGTH
    );
    Ok(())
}

fn decode_frame(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: keepalive_interop decode-frame <path> <direction> <receiver-state>".to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<KEEP_ALIVE_FRAME_LENGTH>(&path)?;
    let FrameParseResult::Accepted { consumed, payload } = parse_remote_frame(&bytes) else {
        return Err("outer frame was not accepted".to_owned());
    };
    if consumed != KEEP_ALIVE_FRAME_LENGTH {
        return Err(format!("unexpected outer-frame boundary: {consumed}"));
    }
    require_keep_alive(payload, message_context)?;
    println!(
        "RUST_KEEPALIVE_FRAME_DECODE_PASS frame_consumed={consumed} payload_consumed={}",
        REMOTE_MESSAGE_CODE_LENGTH
    );
    Ok(())
}

fn encode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: keepalive_interop encode <new-path> <direction> <receiver-state>".to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = encode_remote_message(RemoteMessage::KeepAlive, message_context)
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
        "RUST_KEEPALIVE_ENCODE_PASS bytes={} stateful_effects=NOT_EXECUTED path={}",
        bytes.len(),
        path.display()
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<OsString> = env::args_os().collect();
    match args.get(1).and_then(|value| value.to_str()) {
        Some("decode") => decode(&args),
        Some("decode-frame") => decode_frame(&args),
        Some("encode") => encode(&args),
        _ => Err("usage: keepalive_interop <decode|decode-frame|encode> ...".to_owned()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("keepalive_interop: {error}");
        std::process::exit(1);
    }
}
