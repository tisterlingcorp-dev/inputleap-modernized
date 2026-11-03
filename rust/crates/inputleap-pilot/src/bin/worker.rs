#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "input-leap-rust-worker --status\nWorker bootstrap. Input requires an authenticated supervisor; no standalone capture mode."
        );
        return;
    }
    if args != ["--status"] {
        eprintln!("worker requires authenticated supervisor; standalone input unavailable");
        std::process::exit(1);
    }
    #[cfg(windows)]
    let session = inputleap_platform_windows::control_pipe::current_interactive_session()
        .ok()
        .map(|identity| identity.session_id);
    #[cfg(not(windows))]
    let session = None;
    match serde_json::to_string(&inputleap_pilot::diagnostic_status("worker", session)) {
        Ok(status) => println!("{status}"),
        Err(_) => std::process::exit(1),
    }
}
