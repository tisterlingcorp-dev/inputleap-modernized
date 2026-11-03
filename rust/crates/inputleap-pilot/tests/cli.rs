use std::process::Command;

#[test]
fn standalone_worker_cannot_enable_input() {
    let result = Command::new(env!("CARGO_BIN_EXE_input-leap-rust-worker"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    let status = Command::new(env!("CARGO_BIN_EXE_input-leap-rust-worker"))
        .arg("--status")
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["input_available"], false);
    assert_eq!(status["runtime"]["state"], "stopped");
}

#[test]
fn service_never_starts_or_installs_without_explicit_mode() {
    let result = Command::new(env!("CARGO_BIN_EXE_input-leap-rust-service"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    let status = Command::new(env!("CARGO_BIN_EXE_input-leap-rust-service"))
        .arg("--status")
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["input_available"], false);
    assert_eq!(status["component"], "service");
}

#[cfg(windows)]
#[test]
fn console_host_round_trips_verified_ipc_without_starting_input() {
    use inputleap_control::{
        Command as ControlCommand, PILOT_PIPE_NAME, Request, RuntimeState, SCHEMA_VERSION,
    };
    use inputleap_platform_windows::control_pipe::{
        ControlClient, ExpectedServer, current_interactive_session,
    };
    use std::path::Path;
    use std::time::Duration;

    let identity = match current_interactive_session() {
        Ok(identity) => identity,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let output = Command::new(env!("CARGO_BIN_EXE_input-leap-rust-service"))
                .args(["--console", "--run-for-ms", "10"])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "Session 0 must not host interactive IPC"
            );
            return;
        }
        Err(error) => panic!("cannot inspect current session: {error}"),
    };
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let executable = Path::new(env!("CARGO_BIN_EXE_input-leap-rust-service"));
    let mut child = ChildGuard(
        Command::new(executable)
            .args(["--console", "--run-for-ms", "1000"])
            .spawn()
            .unwrap(),
    );
    // A UI disappearing before sending a frame must not wedge the endpoint.
    drop(
        ControlClient::connect(
            PILOT_PIPE_NAME,
            ExpectedServer::Process {
                executable,
                process_id: child.0.id(),
                session_id: identity.session_id,
                user_sid: &identity.user_sid,
            },
            Duration::from_secs(2),
        )
        .unwrap(),
    );
    for (id, command) in [
        (1, ControlCommand::Status {}),
        (2, ControlCommand::Start {}),
    ] {
        let response = ControlClient::connect(
            PILOT_PIPE_NAME,
            ExpectedServer::Process {
                executable,
                process_id: child.0.id(),
                session_id: identity.session_id,
                user_sid: &identity.user_sid,
            },
            Duration::from_secs(2),
        )
        .unwrap()
        .status(&Request {
            version: SCHEMA_VERSION,
            request_id: id,
            command,
        })
        .unwrap();
        assert_eq!(response.request_id, id);
        assert_ne!(response.status.state, RuntimeState::Connected);
        assert!(response.status.error_code.is_some());
        if id == 2 {
            assert_eq!(
                response.status.error_code.as_deref(),
                Some("pairing_required")
            );
        }
    }
    assert!(child.0.wait().unwrap().success());
}
