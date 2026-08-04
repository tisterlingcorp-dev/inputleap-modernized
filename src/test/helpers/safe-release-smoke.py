from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import winreg


ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / r"out\build\windows-msvc-release-final"
BIN = BUILD / "bin"
QT = BUILD / "qtDeploy"
EXE = (BIN / "input-leap.exe").resolve()
OUT = ROOT / r"out\build\phase113-gates"
RECORD = OUT / "safe-release-smoke-current.json"
LEGACY_SCREENSHOT = OUT / "safe-release-smoke-current.png"
REG_PATH = r"Software\InputLeap\InputLeap"


def sanitize_operational_failure(error) -> dict:
    return {"status": "ERROR", "error_type": type(error).__name__}


def emit_sanitized_failure(error) -> None:
    try:
        print(json.dumps(sanitize_operational_failure(error), ensure_ascii=False))
    except Exception:
        pass


def sanitize_runtime_evidence(processes, connections) -> dict:
    return {
        "process_count": len(processes) if processes is not None else None,
        "connection_count": len(connections) if connections is not None else None,
    }


def invalidate_previous_result(path):
    if path.exists():
        path.write_text(
            '{"pass": false, "status": "INVALIDATED"}\n', encoding="utf-8"
        )
    path.unlink(missing_ok=True)


try:
    invalidate_previous_result(RECORD)
    invalidate_previous_result(LEGACY_SCREENSHOT)
    OUT.mkdir(parents=True, exist_ok=True)
except Exception as error:
    emit_sanitized_failure(error)
    raise SystemExit(1) from None

try:
    import psutil
    from pywinauto import Desktop
except Exception as error:
    emit_sanitized_failure(error)
    raise SystemExit(1) from None


def run_cleanup_steps(steps):
    errors = []
    for name, action in steps:
        try:
            action()
        except Exception as cleanup_error:
            errors.append({
                "step": name,
                "error_type": type(cleanup_error).__name__,
            })
    return errors


def stop_smoke_process(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=8)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def evaluate_ui_observation(texts: list[str]) -> dict:
    normalized = "\n".join(texts).casefold()
    required = (
        "pronto",
        "pronto para conectar",
        "escolha um modo e inicie o inputleap.",
    )
    forbidden = (
        "inicialização bloqueada",
        "initialization blocked",
        "erro",
        "error",
        "falha",
        "failed",
    )
    missing = [marker for marker in required if marker not in normalized]
    found_forbidden = [marker for marker in forbidden if marker in normalized]
    return {
        "pass": not missing and not found_forbidden,
        "missing": missing,
        "forbidden": found_forbidden,
    }


def evaluate_top_windows(windows):
    visible_windows = [window for window in windows if window["visible"]]
    main_window = next(
        (window for window in visible_windows if window["title"] == "InputLeap"),
        None,
    )
    error_windows = [
        window
        for window in visible_windows
        if any(
            term in "\n".join(
                [window["title"], *window.get("uia_texts", [])]
            ).casefold()
            for term in ("erro", "error", "falha", "failed")
        )
    ]
    unexpected_visible_windows = [
        window for window in visible_windows if window is not main_window
    ]
    main_window_enabled = bool(main_window and main_window.get("enabled", False))
    return {
        "pass": (
            main_window is not None
            and main_window_enabled
            and not unexpected_visible_windows
            and not error_windows
        ),
        "error_windows": error_windows,
        "unexpected_visible_windows": unexpected_visible_windows,
        "main_window_enabled": main_window_enabled,
    }


def evaluate_executable_hash(actual: str, expected: str | None) -> dict:
    normalized_actual = actual.casefold()
    normalized_expected = expected.casefold() if expected else None
    return {
        "pass": normalized_expected is not None and normalized_actual == normalized_expected,
        "actual": normalized_actual,
        "expected": normalized_expected,
    }


def evaluate_persisted_state(before: dict, after: dict) -> dict:
    registry_match = before.get("registry") == after.get("registry")
    credentials_match = before.get("credentials") == after.get("credentials")
    return {
        "pass": registry_match and credentials_match,
        "registry_match": registry_match,
        "credentials_match": credentials_match,
    }


def sanitize_ui_evidence(main, top_windows, child_texts, uia_texts) -> dict:
    def window_metadata(window):
        return {
            "visible": bool(window.get("visible")),
            "enabled": bool(window.get("enabled")),
            "rect": list(window.get("rect", [])),
        }

    return {
        "main_window": window_metadata(main),
        "top_windows": [window_metadata(window) for window in top_windows],
        "top_window_count": len(top_windows),
        "child_text_count": len(child_texts),
        "uia_text_count": len(uia_texts),
    }


def enumerate_registry_items(enum_next) -> list:
    items = []
    index = 0
    while True:
        try:
            items.append(enum_next(index))
        except OSError as enumeration_error:
            if getattr(enumeration_error, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                return items
            raise
        index += 1


def registry_snapshot(root, path: str) -> dict:
    def encode(value):
        return {"bytes_hex": value.hex()} if isinstance(value, bytes) else value

    def visit(key) -> dict:
        values = []
        for name, value, value_type in enumerate_registry_items(
            lambda index: winreg.EnumValue(key, index)
        ):
            values.append([name, encode(value), value_type])
        children = {}
        for name in enumerate_registry_items(lambda index: winreg.EnumKey(key, index)):
            with winreg.OpenKey(key, name, 0, winreg.KEY_READ) as child:
                children[name] = visit(child)
        return {"values": sorted(values, key=lambda item: item[0]), "children": children}

    with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
        return visit(key)


def inputleap_credential_metadata() -> list[dict]:
    class CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
        _fields_ = [
            ("Keyword", wt.LPWSTR),
            ("Flags", wt.DWORD),
            ("ValueSize", wt.DWORD),
            ("Value", ctypes.c_void_p),
        ]

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wt.DWORD), ("Type", wt.DWORD), ("TargetName", wt.LPWSTR),
            ("Comment", wt.LPWSTR), ("LastWritten", wt.FILETIME),
            ("CredentialBlobSize", wt.DWORD), ("CredentialBlob", ctypes.c_void_p),
            ("Persist", wt.DWORD), ("AttributeCount", wt.DWORD),
            ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTEW)),
            ("TargetAlias", wt.LPWSTR), ("UserName", wt.LPWSTR),
        ]

    count = wt.DWORD()
    credentials = ctypes.POINTER(ctypes.POINTER(CREDENTIALW))()
    advapi32 = ctypes.windll.advapi32
    if not advapi32.CredEnumerateW("InputLeap/*", 0, ctypes.byref(count), ctypes.byref(credentials)):
        error = ctypes.windll.kernel32.GetLastError()
        if error == 1168:
            return []
        raise ctypes.WinError(error)
    try:
        result = []
        for index in range(count.value):
            credential = credentials[index].contents
            attributes = [
                {
                    "keyword": credential.Attributes[attr].Keyword,
                    "flags": credential.Attributes[attr].Flags,
                    "size": credential.Attributes[attr].ValueSize,
                }
                for attr in range(credential.AttributeCount)
            ]
            result.append({
                "target": credential.TargetName,
                "type": credential.Type,
                "flags": credential.Flags,
                "comment": credential.Comment,
                "last_written": (
                    (credential.LastWritten.dwHighDateTime << 32)
                    | credential.LastWritten.dwLowDateTime
                ),
                "persist": credential.Persist,
                "size": credential.CredentialBlobSize,
                "attributes": attributes,
                "target_alias": credential.TargetAlias,
                "user_name": credential.UserName,
            })
        return sorted(result, key=lambda item: item["target"].casefold())
    finally:
        advapi32.CredFree(credentials)


def persisted_state_snapshot() -> dict:
    return {
        "registry": registry_snapshot(winreg.HKEY_CURRENT_USER, REG_PATH),
        "credentials": inputleap_credential_metadata(),
    }


def product_processes() -> list[dict]:
    names = {"input-leap.exe", "input-leapd.exe", "input-leapc.exe", "input-leaps.exe"}
    result = []
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            if (proc.info["name"] or "").lower() in names:
                result.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(result, key=lambda item: item["pid"])


def relevant_connections() -> list[dict]:
    result = []
    for conn in psutil.net_connections(kind="tcp"):
        local_port = conn.laddr.port if conn.laddr else None
        remote_port = conn.raddr.port if conn.raddr else None
        if local_port not in (24800, 24801, 24810) and remote_port not in (24800, 24801, 24810):
            continue
        result.append({
            "pid": conn.pid,
            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
            "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
            "status": conn.status,
        })
    return result


if not EXE.is_file():
    raise SystemExit("missing release GUI executable")
if not (QT / "platforms" / "qwindows.dll").is_file():
    raise SystemExit("missing release Qt platform plugin")

before_processes = []
before_connections = []
persisted_state_before = {}
proc = None
record = {}
try:
    before_processes = product_processes()
    before_connections = relevant_connections()
    if before_processes or before_connections:
        raise RuntimeError(
            "refusing to disturb existing InputLeap runtime: "
            f"process_count={len(before_processes)}, connection_count={len(before_connections)}"
        )

    persisted_state_before = persisted_state_snapshot()
    env = os.environ.copy()
    env["PATH"] = str(QT) + ";" + str(BIN) + ";" + env.get("PATH", "")
    env["QT_PLUGIN_PATH"] = str(QT)
    env.pop("QT_QPA_PLATFORM", None)
    proc = subprocess.Popen(
        [str(EXE), "--no-autostart-once"],
        cwd=str(BIN),
        env=env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    user32 = ctypes.windll.user32
    top_windows: list[dict] = []
    child_texts: list[str] = []
    enum_proc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @enum_proc
    def collect_top(hwnd, _):
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value != proc.pid:
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title, length + 1)
        rect = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        top_windows.append({
            "hwnd": int(hwnd),
            "title": title.value,
            "visible": bool(user32.IsWindowVisible(hwnd)),
            "enabled": bool(user32.IsWindowEnabled(hwnd)),
            "rect": [rect.left, rect.top, rect.right, rect.bottom],
        })
        return True

    main = None
    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        top_windows.clear()
        user32.EnumWindows(collect_top, 0)
        main = next(
            (window for window in top_windows if window["visible"] and window["title"] == "InputLeap"),
            None,
        )
        if main:
            break
        time.sleep(0.25)

    if not main:
        raise RuntimeError(
            f"main window absent; exit={proc.poll()}, window_count={len(top_windows)}"
        )

    @enum_proc
    def collect_child(hwnd, _):
        length = user32.GetWindowTextLengthW(hwnd)
        if length:
            text = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, text, length + 1)
            if text.value.strip():
                child_texts.append(text.value.strip())
        return True

    # Stabilize, then take a fresh top-level snapshot so a late modal cannot hide.
    time.sleep(2)
    top_windows.clear()
    user32.EnumWindows(collect_top, 0)
    main = next(
        (window for window in top_windows if window["visible"] and window["title"] == "InputLeap"),
        None,
    )
    if not main:
        raise RuntimeError(
            f"main window disappeared after stabilization; window_count={len(top_windows)}"
        )

    for window in top_windows:
        if not window["visible"]:
            window["uia_texts"] = []
            continue
        uia_top = Desktop(backend="uia").window(handle=window["hwnd"])
        window["uia_texts"] = [
            text
            for text in [
                uia_top.window_text().strip(),
                *(element.window_text().strip() for element in uia_top.descendants()),
            ]
            if text
        ]
    top_window_observation = evaluate_top_windows(top_windows)

    user32.EnumChildWindows(main["hwnd"], collect_child, 0)
    uia_texts: list[str] = []
    uia_window = Desktop(backend="uia").window(process=proc.pid, title="InputLeap")
    for element in uia_window.descendants():
        text = element.window_text().strip()
        if text:
            uia_texts.append(text)
    normalized = "\n".join(child_texts + uia_texts).casefold()
    ui_observation = evaluate_ui_observation(uia_texts)
    blocked_markers = [
        marker
        for marker in ("inicialização bloqueada", "initialization blocked")
        if marker in normalized
    ]
    error_top_windows = top_window_observation["error_windows"]
    unexpected_visible_windows = top_window_observation["unexpected_visible_windows"]
    actual = Path(psutil.Process(proc.pid).exe()).resolve()
    executable_hash = evaluate_executable_hash(
        digest(actual), os.environ.get("INPUTLEAP_EXPECTED_RELEASE_SHA256")
    )
    ui_evidence = sanitize_ui_evidence(main, top_windows, child_texts, uia_texts)
    record = {
        "status": "PASS"
        if ui_observation["pass"] and not blocked_markers
        and top_window_observation["pass"]
        else "FAIL",
        "scope": "startup smoke with persisted settings; one-shot automatic start suppression without persisted-state mutation",
        "sha256": executable_hash["actual"],
        "executable_hash": executable_hash,
        "ui_evidence": ui_evidence,
        "ui_observation": ui_observation,
        "blocked_markers": blocked_markers,
        "error_top_window_count": len(error_top_windows),
        "unexpected_visible_window_count": len(unexpected_visible_windows),
        "main_window_enabled": top_window_observation["main_window_enabled"],
        "runtime_before": sanitize_runtime_evidence(before_processes, before_connections),
    }
except Exception as error:
    record = sanitize_operational_failure(error)
    emit_sanitized_failure(error)
finally:
    cleanup = {
        "after_processes": None,
        "after_connections": None,
        "persisted_state": {"pass": False, "registry_match": False, "credentials_match": False},
    }
    cleanup_errors = run_cleanup_steps([
        ("stop_smoke_process", lambda: stop_smoke_process(proc)),

        (
            "snapshot_processes",
            lambda: cleanup.__setitem__("after_processes", product_processes()),
        ),
        (
            "snapshot_connections",
            lambda: cleanup.__setitem__("after_connections", relevant_connections()),
        ),
        (
            "verify_persisted_state",
            lambda: cleanup.__setitem__(
                "persisted_state",
                evaluate_persisted_state(persisted_state_before, persisted_state_snapshot()),
            ),
        ),
    ])
    try:
        after_processes = cleanup["after_processes"]
        after_connections = cleanup["after_connections"]
        persisted_state = cleanup["persisted_state"]
        record["cleanup_errors"] = cleanup_errors
        record["auto_start_restored"] = persisted_state["registry_match"]
        record["credential_state_restored"] = persisted_state["credentials_match"]
        record["runtime_after"] = sanitize_runtime_evidence(after_processes, after_connections)
        record["smoke_process_stopped"] = proc is None or proc.poll() is not None
        record["persisted_state"] = persisted_state
        record["pass"] = (
            not cleanup_errors
            and record.get("status") == "PASS"
            and record.get("executable_hash", {}).get("pass", False)
            and record["auto_start_restored"]
            and record["credential_state_restored"]
            and record["persisted_state"]["pass"]
            and after_processes == []
            and after_connections == []
        )
        print(json.dumps({
            "pass": record.get("pass", False),
            "status": record.get("status", "ERROR"),
            "sha256": record.get("sha256"),
            "blocked_markers": record.get("blocked_markers"),
            "ui_observation": record.get("ui_observation"),
            "error_top_window_count": record.get("error_top_window_count"),
            "auto_start_restored": record.get("auto_start_restored"),
            "credential_state_restored": record.get("credential_state_restored"),
            "persisted_state_preserved": record.get("persisted_state", {}).get("pass"),
        }, ensure_ascii=False), flush=True)
        RECORD.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except Exception as error:
        try:
            invalidate_previous_result(RECORD)
        except Exception:
            pass
        emit_sanitized_failure(error)
        raise SystemExit(1) from None

raise SystemExit(0 if record.get("pass") else 1)
