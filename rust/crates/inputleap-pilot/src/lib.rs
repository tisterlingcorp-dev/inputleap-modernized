#![forbid(unsafe_code)]
//! Native pilot hosts. Input and network capabilities remain unavailable until
//! their authenticated integration is implemented; diagnostic readiness never
//! implies permission to capture, inject or transfer data.

use std::io;
use std::time::Duration;

use inputleap_control::{Command, RuntimeState, SCHEMA_VERSION, StatusSnapshot};
use serde::Serialize;

#[cfg(windows)]
pub mod secure_state;

#[cfg(windows)]
pub mod pairing_control;

#[derive(Debug, Eq, PartialEq)]
pub enum ServiceMode {
    Help,
    Status,
    Query,
    ScmStatus,
    Scm,
    ProvisionScm,
    Revoke { device_id: String },
    Control { command: Command },
    Console { run_for: Duration },
}

pub fn service_mode(args: impl IntoIterator<Item = String>) -> io::Result<ServiceMode> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [flag] if flag == "--help" => Ok(ServiceMode::Help),
        [flag] if flag == "--status" => Ok(ServiceMode::Status),
        [flag] if flag == "--query" => Ok(ServiceMode::Query),
        [flag] if flag == "--scm-status" => Ok(ServiceMode::ScmStatus),
        [flag] if flag == "--service" => Ok(ServiceMode::Scm),
        [flag] if flag == "--service-provision" => Ok(ServiceMode::ProvisionScm),
        [flag, device_id] if flag == "--revoke" => {
            inputleap_types::DeviceId::parse(device_id)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid device ID"))?;
            Ok(ServiceMode::Revoke {
                device_id: device_id.clone(),
            })
        }
        [flag] if flag == "--stop-pilot" => Ok(ServiceMode::Control {
            command: Command::Stop {},
        }),
        [flag, address, bits] if flag == "--pair-connect" || flag == "--pair-listen" => {
            let bits: u8 = bits.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "capabilities must be 0..7")
            })?;
            inputleap_security::Capabilities::from_bits(bits)?;
            let command = if flag == "--pair-connect" {
                Command::BeginPairing {
                    address: address.clone(),
                    capabilities: bits,
                }
            } else {
                Command::ListenPairing {
                    address: address.clone(),
                    capabilities: bits,
                }
            };
            Ok(ServiceMode::Control { command })
        }
        [flag, pairing_id, decision] if flag == "--pair-confirm" => {
            let matches = match decision.as_str() {
                "yes" => true,
                "no" => false,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "compare complete codes, then choose yes or no",
                    ));
                }
            };
            Ok(ServiceMode::Control {
                command: Command::ConfirmPairing {
                    pairing_id: pairing_id.clone(),
                    matches,
                },
            })
        }
        [flag, duration, milliseconds] if flag == "--console" && duration == "--run-for-ms" => {
            let milliseconds: u64 = milliseconds.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid console duration")
            })?;
            if !(1..=60_000).contains(&milliseconds) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "console duration must be 1..60000 ms",
                ));
            }
            Ok(ServiceMode::Console {
                run_for: Duration::from_millis(milliseconds),
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit service mode required; use --help",
        )),
    }
}

#[derive(Serialize)]
pub struct HostStatus {
    pub component: &'static str,
    pub version: &'static str,
    pub runtime: StatusSnapshot,
    pub input_available: bool,
    pub clipboard_available: bool,
    pub files_available: bool,
}

pub fn diagnostic_status(component: &'static str, session: Option<u32>) -> HostStatus {
    HostStatus {
        component,
        version: env!("CARGO_PKG_VERSION"),
        runtime: StatusSnapshot {
            version: SCHEMA_VERSION,
            state: RuntimeState::Stopped,
            worker_session: session.filter(|id| *id != 0),
            pending_input: 0,
            last_processed_sequence: 0,
            error_code: Some("authenticated_runtime_not_ready".into()),
            security: None,
        },
        input_available: false,
        clipboard_available: false,
        files_available: false,
    }
}

/// Only observational commands succeed in this tranche. An unimplemented
/// operation must never look like a successful start, pairing or transfer.
pub fn dispatch_diagnostic(command: &Command) -> StatusSnapshot {
    let mut snapshot = diagnostic_status("service", None).runtime;
    match command {
        Command::Status {} | Command::Diagnostics {} => {}
        Command::Start {} | Command::Reconnect {} => {
            snapshot.state = RuntimeState::AwaitingPairing;
            snapshot.error_code = Some("pairing_required".into());
        }
        Command::Stop {} => snapshot.error_code = None,
        _ => {
            snapshot.state = RuntimeState::Error;
            snapshot.error_code = Some("capability_unavailable".into());
        }
    }
    snapshot
}

#[cfg(windows)]
pub mod windows {
    use super::*;
    use inputleap_control::{PILOT_PIPE_NAME, Request};
    use inputleap_platform_windows::control_pipe::{
        ControlClient, ControlListener, ExpectedServer, active_console_session,
        current_interactive_session,
    };
    use inputleap_platform_windows::service::StopSignal;
    use std::time::Instant;

    pub fn serve_system(stop: StopSignal) -> io::Result<()> {
        let mut security = super::secure_state::PersistentSecurityState::open_existing(
            &inputleap_platform_windows::service::pilot_data_directory()?,
        )?;
        inputleap_platform_windows::service::mark_running()?;
        serve(stop, true, None, Some(&mut security))
    }

    pub fn provision_system(stop: StopSignal) -> io::Result<()> {
        let mut security = super::secure_state::PersistentSecurityState::create_new(
            &inputleap_platform_windows::service::pilot_data_directory()?,
        )?;
        inputleap_platform_windows::service::mark_running()?;
        serve(stop, true, None, Some(&mut security))
    }

    pub fn serve_console(run_for: Duration) -> io::Result<()> {
        current_interactive_session()?;
        serve(StopSignal::default(), false, Some(run_for), None)
    }

    fn serve(
        stop: StopSignal,
        system: bool,
        run_for: Option<Duration>,
        mut security: Option<&mut super::secure_state::PersistentSecurityState>,
    ) -> io::Result<()> {
        let start = Instant::now();
        let mut pairing = super::pairing_control::PairingController::default();
        let mut endpoint = None;
        while !stop.is_stopped() && run_for.is_none_or(|limit| start.elapsed() < limit) {
            let identity = if system {
                active_console_session()?
            } else {
                Some(current_interactive_session()?)
            };
            if let Some(security) = security.as_deref_mut() {
                pairing.poll(identity.as_ref(), security);
            }
            let Some(identity) = identity else {
                endpoint = None;
                std::thread::sleep(Duration::from_millis(200));
                continue;
            };
            if endpoint
                .as_ref()
                .is_none_or(|(owner, _)| owner != &identity)
            {
                drop(endpoint.take());
                endpoint = Some((
                    identity.clone(),
                    ControlListener::bind(
                        PILOT_PIPE_NAME,
                        &identity.user_sid,
                        identity.session_id,
                    )?,
                ));
            }
            let (_, listener) = endpoint
                .as_mut()
                .ok_or_else(|| io::Error::other("pilot endpoint missing"))?;
            match listener.accept_request(Duration::from_millis(500)) {
                Ok(request) => {
                    if stop.is_stopped() {
                        break;
                    }
                    let current = if system {
                        active_console_session()?
                    } else {
                        Some(current_interactive_session()?)
                    };
                    // Recheck the OS identity after parsing, before any command.
                    if current.as_ref() != Some(&identity) {
                        continue;
                    }
                    let status = match security.as_deref_mut() {
                        Some(security) => {
                            let command = &request.request.command;
                            pairing.poll(Some(&identity), security);
                            let action = match command {
                                Command::BeginPairing { .. } | Command::ListenPairing { .. }
                                    if !security.persistence_is_healthy() =>
                                {
                                    Some(Err("security_persistence_failed"))
                                }
                                Command::BeginPairing {
                                    address,
                                    capabilities,
                                } => Some(pairing.begin(
                                    &identity,
                                    security.identity().clone(),
                                    address,
                                    *capabilities,
                                    false,
                                )),
                                Command::ListenPairing {
                                    address,
                                    capabilities,
                                } => Some(pairing.begin(
                                    &identity,
                                    security.identity().clone(),
                                    address,
                                    *capabilities,
                                    true,
                                )),
                                Command::ConfirmPairing {
                                    pairing_id,
                                    matches,
                                } => Some(pairing.confirm(&identity, pairing_id, *matches)),
                                Command::Stop {} | Command::Revoke { .. } => {
                                    pairing.cancel();
                                    None
                                }
                                _ => None,
                            };
                            let mut status = security.dispatch_authorized(command);
                            if action.as_ref().is_some_and(Result::is_ok)
                                && status
                                    .security
                                    .as_ref()
                                    .is_some_and(|security| security.persistence_healthy)
                            {
                                status.state = RuntimeState::Stopped;
                                status.error_code = None;
                            }
                            if action.is_some()
                                || matches!(command, Command::Status {} | Command::Diagnostics {})
                            {
                                pairing.decorate(&identity, &mut status);
                            }
                            if let Some(Err(error)) = action {
                                status.state = RuntimeState::Error;
                                status.error_code = Some(error.into());
                            }
                            status
                        }
                        None => dispatch_diagnostic(&request.request.command),
                    };
                    if let Err(error) = request.respond_status(&status) {
                        // A disconnected UI does not take down the service.
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                        ) {
                            return Err(error);
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::PermissionDenied
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::InvalidData
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn query_installed_service() -> io::Result<inputleap_control::StatusResponse> {
        command_installed_service(Command::Status {})
    }

    pub fn command_installed_service(
        command: Command,
    ) -> io::Result<inputleap_control::StatusResponse> {
        let executable = std::env::current_exe()?.with_file_name("input-leap-rust-service.exe");
        ControlClient::connect(
            PILOT_PIPE_NAME,
            ExpectedServer::WindowsService {
                executable: &executable,
            },
            Duration::from_secs(3),
        )?
        .status(&Request {
            version: SCHEMA_VERSION,
            request_id: 1,
            command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_cli_requires_explicit_rights_and_an_unambiguous_human_decision() {
        for args in [
            vec!["--pair-connect", "127.0.0.1:24920"],
            vec!["--pair-listen", "127.0.0.1:24920", "128"],
            vec!["--pair-confirm", "id", "maybe"],
        ] {
            assert!(service_mode(args.into_iter().map(String::from)).is_err());
        }
        assert!(matches!(
            service_mode(["--pair-confirm", "local-attempt-id", "no"].map(String::from)).unwrap(),
            ServiceMode::Control {
                command: Command::ConfirmPairing { matches: false, .. }
            }
        ));
    }

    #[test]
    fn startup_requires_explicit_mode_and_console_is_bounded() {
        assert!(service_mode(Vec::new()).is_err());
        for args in [
            vec!["--console"],
            vec!["--service", "--console"],
            vec!["--console", "--run-for-ms", "0"],
            vec!["--console", "--run-for-ms", "60001"],
        ] {
            assert!(service_mode(args.into_iter().map(String::from)).is_err());
        }
        assert_eq!(
            service_mode(["--console", "--run-for-ms", "100"].map(String::from)).unwrap(),
            ServiceMode::Console {
                run_for: Duration::from_millis(100)
            }
        );
    }

    #[test]
    fn diagnostic_host_never_claims_unimplemented_capabilities() {
        let status = diagnostic_status("worker", Some(0));
        assert!(!status.input_available && !status.clipboard_available && !status.files_available);
        assert_eq!(status.runtime.worker_session, None);
        assert_eq!(status.runtime.state, RuntimeState::Stopped);
        assert!(status.runtime.error_code.is_some());
    }

    #[test]
    fn input_and_transfer_commands_do_not_succeed_before_authentication() {
        assert_eq!(
            dispatch_diagnostic(&Command::Start {}).state,
            RuntimeState::AwaitingPairing
        );
        assert_eq!(
            dispatch_diagnostic(&Command::Start {})
                .error_code
                .as_deref(),
            Some("pairing_required")
        );
        assert_eq!(
            dispatch_diagnostic(&Command::OfferTransfer {
                offer_id: "test".into()
            })
            .state,
            RuntimeState::Error
        );
        assert_eq!(
            dispatch_diagnostic(&Command::ConfirmPairing {
                pairing_id: "test".into(),
                matches: true
            })
            .error_code
            .as_deref(),
            Some("capability_unavailable")
        );
    }
}
