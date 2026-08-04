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
    let x: i16 = args
        .next()
        .ok_or_else(usage)?
        .to_str()
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| "x must be i16".to_owned())?;
    let y: i16 = args
        .next()
        .ok_or_else(usage)?
        .to_str()
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| "y must be i16".to_owned())?;
    let path = PathBuf::from(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
        return Err(usage());
    }
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::Active,
    );
    match mode.to_str() {
        Some("decode-frame") => {
            if metadata(&path).map_err(|e| e.to_string())?.len() != 12 {
                return Err("frame must be exactly 12 bytes".into());
            }
            let bytes = read(&path).map_err(|e| e.to_string())?;
            if u32::from_be_bytes(bytes[..4].try_into().unwrap()) != 8 || &bytes[4..8] != b"DMRM" {
                return Err("invalid PacketStreamFilter frame".into());
            }
            let parsed = parse_remote_message(&bytes[4..], context);
            if parsed.category != Category::Accepted
                || parsed.consumed != Some(8)
                || parsed.message != Some(RemoteMessage::MouseRelativeMove { dx: x, dy: y })
            {
                return Err(format!("unexpected Rust decode: {parsed:?}"));
            }
            println!("DMRM_RUST_DECODE_PASS x={x} y={y} frame_bytes=12");
        }
        Some("encode-frame") => {
            let mut payload = [0_u8; 8];
            if encode_remote_message_to(
                RemoteMessage::MouseRelativeMove { dx: x, dy: y },
                context,
                &mut payload,
            ) != Ok(8)
            {
                return Err("Rust DMRM encode failed".into());
            }
            let mut frame = [0_u8; 12];
            frame[0..4].copy_from_slice(&8_u32.to_be_bytes());
            frame[4..].copy_from_slice(&payload);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            output.write_all(&frame).map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
            println!("DMRM_RUST_ENCODE_PASS x={x} y={y} frame_bytes=12");
        }
        _ => return Err(usage()),
    }
    Ok(())
}
fn usage() -> String {
    "usage: dmrm_interop <decode-frame|encode-frame> <i16-x> <i16-y> <path>".into()
}
fn main() {
    if let Err(error) = run() {
        eprintln!("dmrm_interop: {error}");
        std::process::exit(1);
    }
}
