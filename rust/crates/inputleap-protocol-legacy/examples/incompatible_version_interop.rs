use inputleap_protocol_legacy::{
    Category, FrameParseResult, RemoteMessage, RemoteMessageContext, RemoteMessageDirection,
    RemoteMessageState, encode_remote_message_to, parse_remote_frame, parse_remote_message,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const EICV_PAYLOAD_LENGTH: usize = 8;
const EICV_FRAME_LENGTH: usize = 12;

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

fn parse_i16(value: &OsStr, field: &str) -> Result<i16, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{field} must be valid Unicode decimal text"))?
        .parse::<i16>()
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

fn require_incompatible_version(
    payload: &[u8],
    message_context: RemoteMessageContext,
) -> Result<(i16, i16), String> {
    let parsed = parse_remote_message(payload, message_context);
    let Some(RemoteMessage::IncompatibleVersion { major, minor }) = parsed.message else {
        return Err(format!(
            "payload was not accepted as IncompatibleVersion in the requested context: {parsed:?}"
        ));
    };
    if parsed.category != Category::Accepted || parsed.consumed != Some(EICV_PAYLOAD_LENGTH) {
        return Err(format!("unexpected EICV parse boundary: {parsed:?}"));
    }
    if !parsed.message.unwrap().is_terminal() {
        return Err("IncompatibleVersion must be terminal parser metadata".to_owned());
    }
    Ok((major, minor))
}

fn decode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: incompatible_version_interop decode <path> <direction> <receiver-state>"
                .to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<EICV_PAYLOAD_LENGTH>(&path)?;
    let (major, minor) = require_incompatible_version(&bytes, message_context)?;
    println!(
        "RUST_EICV_DECODE_PASS consumed={EICV_PAYLOAD_LENGTH} major={major} minor={minor} stateful_effects=NOT_EXECUTED"
    );
    Ok(())
}

fn decode_frame(args: &[OsString]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: incompatible_version_interop decode-frame <path> <direction> <receiver-state>"
                .to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let bytes = read_exact_file::<EICV_FRAME_LENGTH>(&path)?;
    let FrameParseResult::Accepted { consumed, payload } = parse_remote_frame(&bytes) else {
        return Err("outer frame was not accepted".to_owned());
    };
    if consumed != EICV_FRAME_LENGTH {
        return Err(format!("unexpected outer-frame boundary: {consumed}"));
    }
    let (major, minor) = require_incompatible_version(payload, message_context)?;
    println!(
        "RUST_EICV_FRAME_DECODE_PASS frame_consumed={consumed} payload_consumed={EICV_PAYLOAD_LENGTH} major={major} minor={minor}"
    );
    Ok(())
}

fn encode(args: &[OsString]) -> Result<(), String> {
    if args.len() != 7 {
        return Err(
            "usage: incompatible_version_interop encode <new-path> <direction> <receiver-state> <major> <minor>"
                .to_owned(),
        );
    }
    let path = PathBuf::from(&args[2]);
    let message_context = context(&args[3], &args[4])?;
    let major = parse_i16(&args[5], "major")?;
    let minor = parse_i16(&args[6], "minor")?;
    let mut bytes = [0_u8; EICV_PAYLOAD_LENGTH];
    let written = encode_remote_message_to(
        RemoteMessage::IncompatibleVersion { major, minor },
        message_context,
        &mut bytes,
    )
    .map_err(|error| format!("encode rejected requested message: {error:?}"))?;
    if written != EICV_PAYLOAD_LENGTH {
        return Err(format!("unexpected EICV encoded length: {written}"));
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
        "RUST_EICV_ENCODE_PASS bytes={written} major={major} minor={minor} stateful_effects=NOT_EXECUTED path={}",
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
        _ => Err("usage: incompatible_version_interop <decode|decode-frame|encode> ...".to_owned()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("incompatible_version_interop: {error}");
        std::process::exit(1);
    }
}
