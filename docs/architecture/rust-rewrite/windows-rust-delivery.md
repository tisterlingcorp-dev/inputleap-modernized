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
| Rust pilot hosts | Separate native SCM service and diagnostic Windows worker binaries | Authenticated worker launch, productive input/clipboard/files |
| Rust server | mTLS socket and polling Windows capture | Pair-bound productive session and event capture |
| Windows backend | SendInput, primary display and basic keys/buttons | Extended keys, wheel, DPI, virtual desktop, hooks, release state |
| Transfer | Queue of complete buffers, maximum 16 MiB | Consent, streaming, resume, secure atomic publication |
| Security | Separate tested Rust pilot identity, bilateral pairing and exporter/channel/role binding | Windows protected persistence, durable revocation, service/UI pairing integration |
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
derives PID/token/session/SID from Windows and validates them before dispatch.
Request fields never grant identity. Pairing handles, transfer offers and status
contain no private keys or clipboard content. Framing is bounded to 64 KiB with a
big-endian u32 byte length; unknown fields, versions and truncated messages fail.
The endpoint is implemented in the Windows platform crate with actual OS pipe
tests. It retains a single first-instance listener and serializes exchanges under
an exclusive borrow. Every exchange has a deadline; client token impersonation is
reverted before returning an authorized request. Responses carry the originating
request ID. After validating and consuming a response the client sends the single
receipt byte `0xa5`; only then may the server disconnect, preventing Windows from
discarding unread response bytes. Disappearing or malformed clients reset their
connection without releasing the namespace or stopping the host.

The client requests identification-only SQOS, pins the server executable by file
identity and keeps its process handle open. Production service identity additionally
requires Session 0 and a matching live dedicated `InputLeapRustPilot` LocalSystem
PID obtained from SCM. It does not rely on an ordinary UI being allowed to query a
SYSTEM process token. Explicit development process pins are separate; SCM errors
never downgrade to development trust.

`inputleap-pilot` builds `input-leap-rust-service` and `input-leap-rust-worker` as
members of the root workspace, so all existing pilot gates include both binaries.
The service has a native SCM entry point, STOP/SHUTDOWN handling and a read-only
diagnostic dispatcher scoped to the active physical console's OS identity. It
remains alive without a logged-on console user. Console-mode development hosts
require an explicit bounded run duration and an interactive session. The worker
is currently a diagnostic bootstrap: neither host claims productive input, file
or clipboard capabilities. Standalone execution never starts input. Pairing and
transfer commands report unavailable, and Start/Reconnect require pairing. Worker
creation, productive authentication and UI integration remain subsequent work.

`scripts/windows/smoke_rust_service.ps1` is an elevated development/CI test, not the
product installer. It refuses existing service/directory collisions, temporarily
copies the two hashes-verified Release executables into a separate protected
Program Files pilot folder, registers Manual LocalSystem startup, verifies native
SCM identity and interactive IPC when available, stops/deletes the service and
removes only its known unchanged files and empty directory. No recursive cleanup
or operational InputLeap mutation occurs. On Session 0 CI hosts the report must
explicitly distinguish unexercised interactive IPC from the SCM lifecycle test.
An actual local interactive test has exercised the full native SCM/IPC path.

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
