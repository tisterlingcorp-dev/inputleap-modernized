use inputleap_control::{Command, Request, SCHEMA_VERSION};

fn decode(payload: serde_json::Value) -> Result<Command, String> {
    let command: Command =
        serde_json::from_value(payload).map_err(|_| "Comando piloto inválido".to_string())?;
    if !matches!(
        command,
        Command::Status {}
            | Command::Diagnostics {}
            | Command::BeginPairing { .. }
            | Command::ListenPairing { .. }
            | Command::ConfirmPairing { .. }
            | Command::Revoke { .. }
            | Command::Stop {}
    ) {
        return Err("Ação ainda não disponível no piloto Rust".into());
    }
    Request {
        version: SCHEMA_VERSION,
        request_id: 1,
        command: command.clone(),
    }
    .validate()
    .map_err(|_| "Parâmetros piloto inválidos".to_string())?;
    Ok(command)
}

#[tauri::command]
pub async fn pilot_command(
    window: tauri::WebviewWindow,
    payload: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let url = window.url().map_err(|_| "Origem indisponível")?;
    if !authorized_origin(
        std::env::args().any(|argument| argument == "--rust-pilot"),
        window.label(),
        &url,
    ) {
        return Err("Acesso restrito à janela do piloto".into());
    }
    let command = decode(payload)?;
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(move || {
            let response = query(command)
                .map_err(|_| "Serviço piloto indisponível ou sessão não autorizada".to_string())?;
            serde_json::to_value(response).map_err(|_| "Resposta piloto inválida".to_string())
        })
        .await
        .map_err(|_| "Consulta piloto interrompida".to_string())?
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Err("Piloto disponível somente no Windows".into())
    }
}

fn authorized_origin(pilot: bool, label: &str, url: &tauri::Url) -> bool {
    pilot
        && label == "main"
        && url.path() == "/pilot.html"
        && url.query().is_none()
        && ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
            || (url.scheme() == "http"
                && url.host_str() == Some("tauri.localhost")
                && url.port().is_none()))
}

#[cfg(windows)]
fn query(command: Command) -> std::io::Result<inputleap_control::StatusResponse> {
    use inputleap_platform_windows::{
        control_pipe::{ControlClient, ExpectedServer},
        service::pilot_install_directory,
    };
    let executable = pilot_install_directory()?.join("input-leap-rust-service.exe");
    ControlClient::connect(
        inputleap_control::PILOT_PIPE_NAME,
        ExpectedServer::WindowsService {
            executable: &executable,
        },
        std::time::Duration::from_secs(3),
    )?
    .status(&Request {
        version: SCHEMA_VERSION,
        request_id: 1,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pilot_origin_is_local_exact_and_never_enabled_in_legacy_mode() {
        let valid = tauri::Url::parse("http://tauri.localhost/pilot.html").unwrap();
        assert!(authorized_origin(true, "main", &valid));
        assert!(!authorized_origin(false, "main", &valid));
        assert!(!authorized_origin(true, "other", &valid));
        for url in [
            "https://example.invalid/pilot.html",
            "http://localhost/pilot.html",
            "http://tauri.localhost:8080/pilot.html",
            "http://tauri.localhost/index.html",
            "http://tauri.localhost/pilot.html?remote=1",
        ] {
            assert!(!authorized_origin(
                true,
                "main",
                &tauri::Url::parse(url).unwrap()
            ));
        }
    }
    #[test]
    fn webview_cannot_call_runtime_or_supply_an_identity() {
        for payload in [
            serde_json::json!({"type":"start"}),
            serde_json::json!({"type":"accept_transfer","offer_id":"x","destination":"C:\\x"}),
            serde_json::json!({"type":"status","session_id":1}),
            serde_json::json!({"type":"listen_pairing","address":"127.0.0.1:24920","capabilities":128}),
        ] {
            assert!(decode(payload).is_err());
        }
        assert!(decode(serde_json::json!({"type":"status"})).is_ok());
    }
}
