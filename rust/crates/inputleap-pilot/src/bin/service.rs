#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use inputleap_pilot::{ServiceMode, diagnostic_status, service_mode};
use std::io;

fn run() -> io::Result<()> {
    match service_mode(std::env::args().skip(1))? {
        ServiceMode::Help => println!(
            "input-leap-rust-service --status | --query | --scm-status | --service | --service-provision | --console --run-for-ms 1..60000\nSeparate Rust pilot. Provisioning requires explicit LocalSystem SCM installation; does not enable input."
        ),
        ServiceMode::Status => println!(
            "{}",
            serde_json::to_string(&diagnostic_status("service", None))?
        ),
        mode => run_platform(mode)?,
    }
    Ok(())
}

#[cfg(windows)]
fn run_platform(mode: ServiceMode) -> io::Result<()> {
    match mode {
        ServiceMode::Scm => {
            inputleap_platform_windows::service::run_service(inputleap_pilot::windows::serve_system)
        }
        ServiceMode::ProvisionScm => inputleap_platform_windows::service::run_service(
            inputleap_pilot::windows::provision_system,
        ),
        ServiceMode::Console { run_for } => inputleap_pilot::windows::serve_console(run_for),
        ServiceMode::Query => {
            println!(
                "{}",
                serde_json::to_string(&inputleap_pilot::windows::query_installed_service()?)?
            );
            Ok(())
        }
        ServiceMode::ScmStatus => {
            let pid = inputleap_platform_windows::service::verified_system_service_pid()?;
            println!(
                "{}",
                serde_json::json!({"service_pid":pid,"account":"LocalSystem","state":"running"})
            );
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid runtime mode",
        )),
    }
}

#[cfg(not(windows))]
fn run_platform(_: ServiceMode) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows x64 pilot required",
    ))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("input-leap-rust-service: {error}");
        std::process::exit(1);
    }
}
