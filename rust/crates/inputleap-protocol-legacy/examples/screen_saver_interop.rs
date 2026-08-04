use inputleap_protocol_legacy::{
    Category, FrameParseResult, RemoteMessage, RemoteMessageContext, RemoteMessageDirection,
    RemoteMessageState, encode_remote_message_to, parse_remote_frame, parse_remote_message,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const CSEC_PAYLOAD_LENGTH: usize = 5;
const CSEC_FRAME_LENGTH: usize = 9;

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

fn parse_u8(value: &OsStr, field: &str) -> Result<u8, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{field} must be valid Unicode decimal text"))?
        .parse::<u8>()
        .map_err(|error| format!("invalid {field}: {error}"))
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

fn require_screen_saver(
    payload: &[u8],
    message_context: RemoteMessageContext,
) -> Result<u8, String> {
    let parsed = parse_remote_message(payload, message_context);
    let Some(RemoteMessage::ScreenSaver { raw }) = parsed.message else {
        return Err(format!(
            "payload was not accepted as ScreenSaver in the requested context: {parsed:?}"
        ));
    };
    if parsed.category != Category::Accepted || parsed.consumed != Some(CSEC_PAYLOAD_LENGTH) {
        return Err(format!("unexpected CSEC parse boundary: {parsed:?}"));
    }
    if parsed.message.unwrap().is_terminal() {
        return Err("ScreenSaver must be nonterminal parser metadata".to_owned());
    }
    Ok(raw)
}

fn decode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: screen_saver_interop decode <path> <direction> <receiver-state>".to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<CSEC_PAYLOAD_LENGTH>(&path)?;
    let raw = require_screen_saver(&bytes, message_context)?;
    let active = raw != 0;
    println!(
        "RUST_CSEC_DECODE_PASS consumed={CSEC_PAYLOAD_LENGTH} raw={raw} active={active} terminal=false stateful_effects=NOT_EXECUTED"
    );
    Ok(())
}

fn decode_frame(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: screen_saver_interop decode-frame <path> <direction> <receiver-state>"
                .to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<CSEC_FRAME_LENGTH>(&path)?;
    let FrameParseResult::Accepted { consumed, payload } = parse_remote_frame(&bytes) else {
        return Err("outer frame was not accepted".to_owned());
    };
    if consumed != CSEC_FRAME_LENGTH {
        return Err(format!("unexpected outer-frame boundary: {consumed}"));
    }
    let raw = require_screen_saver(payload, message_context)?;
    let active = raw != 0;
    println!(
        "RUST_CSEC_FRAME_DECODE_PASS frame_consumed={consumed} payload_consumed={CSEC_PAYLOAD_LENGTH} raw={raw} active={active} terminal=false stateful_effects=NOT_EXECUTED"
    );
    Ok(())
}

fn encode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 6 {
        return Err(
            "usage: screen_saver_interop encode <new-path> <direction> <receiver-state> <raw-u8>"
                .to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let raw = parse_u8(&args[5], "raw-u8")?;
    let mut bytes = [0_u8; CSEC_PAYLOAD_LENGTH];
    let written = encode_remote_message_to(
        RemoteMessage::ScreenSaver { raw },
        message_context,
        &mut bytes,
    )
    .map_err(|error| format!("encode rejected requested message: {error:?}"))?;
    if written != CSEC_PAYLOAD_LENGTH {
        return Err(format!("unexpected CSEC encoded length: {written}"));
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("unable to create output exclusively: {error}"))?;
    output
        .write_all(&bytes)
        .map_err(|error| format!("unable to write output: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("unable to flush output: {error}"))?;
    println!(
        "RUST_CSEC_ENCODE_PASS bytes={written} raw={raw} active={} stateful_effects=NOT_EXECUTED path={}",
        raw != 0,
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
        _ => Err("usage: screen_saver_interop <decode|decode-frame|encode> ...".to_owned()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("screen_saver_interop: {error}");
        std::process::exit(1);
    }
}
