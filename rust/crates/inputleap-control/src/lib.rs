#![forbid(unsafe_code)]
//! Versioned local control contract for the isolated Windows Rust pilot.
//!
//! Parsing a request never authenticates its sender. The named-pipe server must
//! derive the caller identity from Windows and authorize each command before
//! dispatch. No identity or secret supplied by the WebView grants authority.

pub mod input;
pub mod supervisor;

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;
pub const PILOT_INPUT_PORT: u16 = 24_900;
pub const PILOT_DATA_PORT: u16 = 24_910;
pub const PILOT_PIPE_NAME: &str = r"\\.\pipe\InputLeapRustPilot.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Stopped,
    Discovering,
    AwaitingPairing,
    Connecting,
    Connected,
    Recovering,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Discover {},
    BeginPairing {
        address: String,
    },
    ConfirmPairing {
        pairing_id: String,
        matches: bool,
    },
    Start {},
    Stop {},
    Reconnect {},
    Revoke {
        device_id: String,
    },
    OfferTransfer {
        offer_id: String,
    },
    AcceptTransfer {
        offer_id: String,
        destination: String,
    },
    CancelTransfer {
        transfer_id: String,
    },
    Diagnostics {},
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub request_id: u64,
    pub command: Command,
}

impl Request {
    /// Validates structure only; pairing, paths and permissions require domain checks.
    pub fn validate(&self) -> io::Result<()> {
        if self.version != SCHEMA_VERSION || self.request_id == 0 {
            return Err(invalid("unsupported version or missing request ID"));
        }
        let fields: Vec<(&str, usize)> = match &self.command {
            Command::BeginPairing { address } => vec![(address, 255)],
            Command::ConfirmPairing { pairing_id, .. } => vec![(pairing_id, 128)],
            Command::Revoke { device_id } => vec![(device_id, 128)],
            Command::OfferTransfer { offer_id } => vec![(offer_id, 128)],
            Command::AcceptTransfer {
                offer_id,
                destination,
            } => {
                vec![(offer_id, 128), (destination, 32_767)]
            }
            Command::CancelTransfer { transfer_id } => vec![(transfer_id, 128)],
            _ => Vec::new(),
        };
        if fields.iter().any(|(value, limit)| {
            value.trim().is_empty() || value.len() > *limit || value.chars().any(char::is_control)
        }) {
            return Err(invalid("invalid command field"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshot {
    pub version: u16,
    pub state: RuntimeState,
    pub worker_session: Option<u32>,
    pub pending_input: u32,
    pub last_processed_sequence: u64,
    /// Stable public code, never raw OS errors containing paths or content.
    pub error_code: Option<String>,
}

/// Every response is correlated to the command on its authenticated pipe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub version: u16,
    pub request_id: u64,
    pub status: StatusSnapshot,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Reads a bounded frame before allocating its payload. Clean EOF is distinct
/// from a truncated header/payload, which must close the IPC connection.
pub fn read_request(reader: &mut impl Read) -> io::Result<Option<Request>> {
    let mut header = [0; 4];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_CONTROL_FRAME {
        return Err(invalid("invalid control frame length"));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    let request: Request =
        serde_json::from_slice(&payload).map_err(|_| invalid("invalid control request"))?;
    request.validate()?;
    Ok(Some(request))
}

pub fn write_request(writer: &mut impl Write, request: &Request) -> io::Result<()> {
    request.validate()?;
    let payload = serde_json::to_vec(request).map_err(|_| invalid("invalid control request"))?;
    if payload.len() > MAX_CONTROL_FRAME {
        return Err(invalid("oversized control frame"));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn request() -> Request {
        Request {
            version: SCHEMA_VERSION,
            request_id: 1,
            command: Command::Start {},
        }
    }

    #[test]
    fn concatenated_frames_keep_message_boundaries() {
        let mut stream = Vec::new();
        write_request(&mut stream, &request()).unwrap();
        write_request(
            &mut stream,
            &Request {
                request_id: 2,
                command: Command::Stop {},
                ..request()
            },
        )
        .unwrap();
        let mut stream = Cursor::new(stream);
        assert_eq!(read_request(&mut stream).unwrap(), Some(request()));
        assert_eq!(read_request(&mut stream).unwrap().unwrap().request_id, 2);
        assert!(read_request(&mut stream).unwrap().is_none());
    }

    #[test]
    fn truncated_frames_are_not_clean_eof() {
        let mut frame = Vec::new();
        write_request(&mut frame, &request()).unwrap();
        for length in 1..frame.len() {
            assert!(read_request(&mut &frame[..length]).is_err());
        }
    }

    #[test]
    fn untrusted_lengths_rejected_without_reading_payload() {
        for length in [0, MAX_CONTROL_FRAME as u32 + 1, u32::MAX] {
            assert_eq!(
                read_request(&mut &length.to_be_bytes()[..])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn unknown_fields_cannot_supply_an_identity() {
        let json = br#"{"version":1,"request_id":1,"command":{"type":"start","session_id":1}}"#;
        let mut frame = (json.len() as u32).to_be_bytes().to_vec();
        frame.extend(json);
        assert!(read_request(&mut &frame[..]).is_err());
    }

    #[test]
    fn invalid_requests_never_write_partial_frames() {
        for value in [
            Request {
                version: 2,
                ..request()
            },
            Request {
                request_id: 0,
                ..request()
            },
            Request {
                command: Command::BeginPairing {
                    address: "\0host".into(),
                },
                ..request()
            },
        ] {
            let mut output = Vec::new();
            assert!(write_request(&mut output, &value).is_err());
            assert!(output.is_empty());
        }
    }
}
