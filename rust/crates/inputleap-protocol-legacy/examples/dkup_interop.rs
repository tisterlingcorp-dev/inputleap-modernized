use inputleap_protocol_legacy::{
    Category, RemoteMessage, RemoteMessageContext, RemoteMessageDirection, RemoteMessageState,
    encode_remote_message_to, parse_remote_message,
};
use std::env;
use std::fs::{OpenOptions, metadata, read};
use std::io::Write;
use std::path::PathBuf;

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let mode = args.next().ok_or_else(usage)?;
    let key_id = parse_u16(args.next(), "key-id")?;
    let modifier_mask = parse_u16(args.next(), "modifier-mask")?;
    let button = parse_u16(args.next(), "button")?;
    let path = PathBuf::from(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
        return Err(usage());
    }
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::Active,
    );
    let message = RemoteMessage::KeyUp {
        key_id,
        modifier_mask,
        button,
    };
    match mode.to_str() {
        Some("decode-frame") => {
            if metadata(&path).map_err(|e| e.to_string())?.len() != 14 {
                return Err("frame must be exactly 14 bytes".into());
            }
            let bytes = read(&path).map_err(|e| e.to_string())?;
            if u32::from_be_bytes(bytes[..4].try_into().unwrap()) != 10 || &bytes[4..8] != b"DKUP" {
                return Err("invalid PacketStreamFilter frame".into());
            }
            let parsed = parse_remote_message(&bytes[4..], context);
            if parsed.category != Category::Accepted
                || parsed.consumed != Some(10)
                || parsed.message != Some(message)
            {
                return Err(format!("unexpected Rust decode: {parsed:?}"));
            }
            println!(
                "DKUP_RUST_DECODE_PASS key_id={key_id} modifier_mask={modifier_mask} button={button} frame_bytes=14"
            );
        }
        Some("encode-frame") => {
            let mut payload = [0_u8; 10];
            if encode_remote_message_to(message, context, &mut payload) != Ok(10) {
                return Err("Rust DKUP encode failed".into());
            }
            let mut frame = [0_u8; 14];
            frame[0..4].copy_from_slice(&10_u32.to_be_bytes());
            frame[4..].copy_from_slice(&payload);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            output.write_all(&frame).map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
            println!(
                "DKUP_RUST_ENCODE_PASS key_id={key_id} modifier_mask={modifier_mask} button={button} frame_bytes=14"
            );
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn parse_u16(value: Option<std::ffi::OsString>, name: &str) -> Result<u16, String> {
    value
        .ok_or_else(usage)?
        .to_str()
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| format!("{name} must be u16"))
}

fn usage() -> String {
    "usage: dkup_interop <decode-frame|encode-frame> <u16-key-id> <u16-modifier-mask> <u16-button> <path>".into()
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dkup_interop: {error}");
        std::process::exit(1);
    }
}
