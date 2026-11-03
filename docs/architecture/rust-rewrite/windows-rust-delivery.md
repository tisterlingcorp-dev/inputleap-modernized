# Windows Rust delivery

Status: implementation started, not a replacement runtime. This supersedes the
previous architectural target of shipping C++/Qt indefinitely. The operational
hybrid installation stays installed until the separate Rust pilot is accepted.

## Product boundary

Windows 10/11 x64; Tauri UI, Rust supervisor service and one authorized interactive
worker per session. No Qt, C++ runtime, Bonjour, external watchdog, or legacy
protocol fallback in the final package. Linux/macOS and secure-desktop input are
outside acceptance. No transport or performance property follows from language
choice alone.

## Inventory at implementation start

| Component | Observed implementation | Missing production evidence/work |
| --- | --- | --- |
| Tauri | Existing operational UI supervises C++ over TCP IPC | Rust named pipe integration and real state |
| Rust agent | Standalone X11 backend; rejects Windows | Windows worker, truthful status, session ownership |
| Rust server | mTLS socket and polling Windows capture | Pair-bound productive session and event capture |
| Windows backend | SendInput, primary display and basic keys/buttons | Extended keys, wheel, DPI, virtual desktop, hooks, release state |
| Transfer | Queue of complete buffers, maximum 16 MiB | Consent, streaming, resume, secure atomic publication |
| Security | Rust mTLS and control-auth primitives with unit tests | Exporter/channel/role binding, Windows protected persistence, UI pairing |
| Recovery | Existing operational external scripts | Rust supervisor and worker-progress acknowledgements |
| Packaging | Hybrid package and historical CI evidence | Independent Rust installer and Windows 10/11 lifecycle |

Existing workspace baseline: 153 tests passed on Windows before changes. Separate
agent/server/Tauri manifests are not covered by `cargo test --workspace` at rust/.
The dedicated Windows pilot gate explicitly validates all four manifests. Passing
these gates is necessary, not proof of interactive or installer parity.

## Control contract and process isolation

`inputleap-control` defines v1 local command framing, statuses and deterministic
supervisor policies. Pilot pipe: `\\.\pipe\InputLeapRustPilot.v1`; input TCP 24900;
data TCP 24910. These are distinct from the operational C++ ports.

The Windows platform pipe endpoint rejects remote pipe clients, uses a restrictive DACL,
derive PID/token/session/SID from Windows and validate them before dispatch.
Request fields never grant identity. Pairing handles, transfer offers and status
contain no private keys or clipboard content. Framing is bounded to 64 KiB with a
big-endian u32 byte length; unknown fields, versions and truncated messages fail.
The endpoint is implemented in the Windows platform crate with actual OS pipe
tests. It uses a single-request deadline, first-instance enforcement and client
token impersonation reverted before returning an authorized request. Status
responses carry the originating request ID. No application dispatcher, SCM
service registration or worker launch is implemented yet; the contract crate
alone never authorizes an operation. Client-side verification of the supervisor
identity is still required before the UI uses this endpoint.

The worker must not run in Session 0 or on the secure desktop. Network failures
retry at 1/2/4/8/16/30 seconds with OS-random jitter (up to 250 ms, capped at 30 s).
Network/resume notifications reset retry scheduling. A connected worker with
pending input and no processing progress is different from an idle worker.
At most three worker restarts are permitted in a rolling minute. A supervisor
must enforce single-instance ownership and session authorization separately.

## Kanban and release acceptance

The user's Obsidian board is the operational source for R01–R12 state and private
machine evidence. Repository docs hold portable contracts, tests and procedures.
Every card records dependencies, acceptance, tests, current revision, problems,
solutions and next action. One card implementing and one validating maximum.
No card is complete on source changes or unexecuted test definitions alone.

Acceptance: authenticated input/clipboard/files; Unicode, images, empty and 5 GiB
files, folders; ten recovery cycles per failure mode and five reboots per machine;
two eight-hour pilot days; Windows 10/11 clean install/upgrade/repair/uninstall/
rollback; final SHA CI and dependency policy; SBOM, notices, hashes and signing
when a certificate exists. Do not publish until all acceptance gates pass.

Compare Release builds under the same conditions. Initial targets: 20% smaller
installer and idle process-tree memory; p95 local input queue <=5 ms; transfer adds
<=10 ms to p95 input acknowledgement in a controlled network. ICMP round trips
on live Wi-Fi are not input-latency evidence. Count WebView2 children in full
memory measurements and separate prerequisite downloads from installer size.

`scripts/windows/measure_rust_migration_baseline.ps1` captures non-invasive initial
observations into ignored output. It labels unavailable counters and incomplete
process-tree measurements explicitly. An observed live-session baseline does not
satisfy the controlled idle benchmark.
