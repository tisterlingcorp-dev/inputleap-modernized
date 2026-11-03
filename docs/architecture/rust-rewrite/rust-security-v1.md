# Rust pilot security v1

Status: implemented as a separate library, with real loopback tests. Not yet
connected to the Windows service/UI or durable protected storage. R03 remains
in progress; these tests do not prove the complete product or worker input path.

## Identity and storage boundary

`inputleap-security` uses per-device UUIDs, Ed25519 signatures and a self-signed
certificate with a logical `<device-id>.inputleap.invalid` SAN, digital-signature
usage and server/client EKUs. Generated certificates last one year; expired and
future-dated leaf certificates are rejected by TLS. Names identify devices, not
OS accounts, public DNS or network discovery addresses.

Public identity parsing verifies bounded DER, logical SAN and Ed25519 SPKI. It
does not confer trust. Private restore verifies the key matches the certificate.
Secret buffers are zeroized on drop and have redacted Debug implementations.
`SecretMaterial` is a private-record buffer prepared **for** OS protection; it is
not encrypted by itself. No plaintext file-storage helper exists. Durable Windows
DPAPI/ACL storage, peer-record integrity and revocation after reboot are still
required. Do not route this material through Tauri, logs or process arguments.

## Pairing is not application authorization

The caller must open a temporary pairing window through an authenticated local
operator action; the library does not start a listener automatically. A bounded
public-certificate preface is followed by TLS 1.3 with mutual certificate possession
and validity checks. Provisional roots exist only for this pairing session and
never grant input/clipboard/files. No custom accept-all certificate verifier or
public web root store is used.

Each side signs an offer bound to its peer, connection role, requested permissions,
fresh OS nonce and TLS exporter. Both views compute the same 96-bit comparison
code from the full transcript. The operators must compare all six hexadecimal
groups on their own screens. Both signed confirmations must match the transcript
and approve only a subset of proposed permissions; no authority is returned after
one rejection, invalid signature or a 60-second confirmation expiry.

The pairing object exposes no application-frame API. After confirmation the
pairing connection closes. Production input/data require a fresh mutually trusted
TLS connection using the resulting peer authority. Persistent stores must reject
identity/key substitutions rather than silently overwrite an existing device.
Pairing-window rate limits, human UI actions and durable commit are integration
work, not properties inferred from the library API.

## Authorized sessions and revocation

Input and data are separate TLS 1.3 connections. Every session requires a signed
hello binding sender, recipient, connector/listener role, channel, permissions,
fresh nonce and the current TLS exporter. Permissions are intersected; unknown
bits, wrong identity/role/channel and another TLS session's signature fail closed.

Application frames carry bounded length, operation and monotonic u64 sequence.
Input cannot be delivered on the data socket, clipboard/files cannot be delivered
on the input socket, and permissions are checked before payload allocation and
after reception. Invalid frames close the connection. Idle timeout before a frame
is distinct from a timeout after the first frame byte, which is fatal.

Cloned peer authorities share in-memory revocation state. Revocation blocks new
sessions/operations and shuts down registered sockets. Windows may not wake an
already blocked read after shutdown on a duplicated socket; cancellable reads
therefore bound individual OS waits to 50 ms while preserving the overall deadline.
Tests hold the opposite endpoint open when verifying revocation, so EOF cannot
mistakenly satisfy the test. Worker queue barriers and release of pressed keys
are R04/R05 integration work; durable revocation is still R03 work.

Limits: certificate DER 16 KiB, private key DER 4 KiB, public preface bounded before
allocation, signed authorization hello 139 bytes, input payload 4 KiB, data payload
320 KiB and eight live application sessions per peer. Underlying TLS IO enforces
absolute deadlines between OS reads/writes so slow byte streams cannot reset a
handshake budget indefinitely. The service must additionally bound concurrent
unauthenticated handshakes and pairing attempts.

## Executed evidence

The library test suite exercises real certificates, provisional pairing, signed
operator decisions and separate authenticated loopback sockets. Cases include:

- missing one/both operator approvals; narrowing permissions; fresh comparison codes;
- correct Unicode bytes over an authorized data socket (not Windows clipboard parity);
- substituted certificate/key/device, expired/future certificates, missing client
  certificate and TLS 1.2 rejection;
- actual-session exporter replay, identity/role/channel substitution and signature tamper;
- duplicate application sequence, remote oversized frames and cross-channel operations;
- stalled/dripping prefices, idle versus partial-frame timeout, live revocation;
- private-record validation/redaction without claiming DPAPI encryption.

No test captures or injects desktop input, reads the user's clipboard, writes a
credential store, installs a runtime or creates a real pairing on either laptop.

## Windows DPAPI boundary

`inputleap-platform-windows::protected_data` provides bounded current-account
DPAPI protection with UI forbidden and no `LOCAL_MACHINE` or plaintext fallback.
Identity and peer-registry records use distinct stable purpose entropy; this is
domain separation, not a secret/password. Decrypted buffers and Win32 output
allocations are zeroized; Debug never exposes plaintext. Threads impersonating
an IPC caller are rejected before either operation. Production use belongs in
the dedicated service after reverting to its own identity.

Five Windows tests cover randomized ciphertext/round trip, purpose confusion,
tampering/plaintext rejection, empty/oversized records, actual device-identity
restoration and rejection during thread impersonation. Tests use the test
process account; LocalSystem lifecycle integration and cross-account denial
are not established by these tests. This is not yet an ACL-protected atomic
filesystem store or a durable revocation registry, and is not wired into the
service/UI. In particular DPAPI does not prevent rollback to an older valid blob.

## Atomic Windows record store

`protected_store::ProtectedStore` creates a single private directory with an
explicit protected DACL and owner from the process token. Current-account stores
grant full access only to that account and LocalSystem. LocalSystem-owned service
stores grant full access to SYSTEM and trusted Administrators for installation/
recovery; DPAPI still denies decryption under the administrator's own account.
ACL/owner are checked against the generated exact
descriptor on open/load/save; inherited or broader existing ACLs are rejected,
never repaired. File handles reject reparse points and multiple hard links.
The root remains non-delete-shared; a separate `writer.lock` excludes concurrent
writers without blocking Win32 child-file rename operations.

The only record names are `identity.dpapi` and `peers.dpapi`. Writes use a fixed
private staging file, `sync_all`, then same-directory MoveFileEx with replacement
and write-through. Existing destination data must decrypt before replacement;
corrupt records never become a silent identity reset. A later save validates and
removes only its exact staging file left by an interrupted attempt. It does not
publish an uncommitted staging record. A failed rename preserves the old record.

The caller must supply a fixed path under a trusted parent, not a UI/network
path; the module does not secure arbitrary ancestor directories. Production
LocalSystem provisioning, schema validation of peer records, durable revocation
and service integration remain separate work. Five Windows filesystem tests
cover private create/replace/reopen/exclusive writer, rejection of an inherited
directory without changing its marker, corrupt-record no-reset, failed rename
with subsequent staging recovery, and hard-link rejection. No user configuration
or production credential directory is opened by these tests.

## Persisted peer authority

`PeerRegistry` encodes a bounded, versioned record bound to both local device ID
and certificate fingerprint. It rejects self/duplicate devices, trailing or
truncated records, unknown capabilities/revocation states and over-capacity
input before issuing authority. Restore is a privileged API: its caller must
first authenticate/decrypt the record through the private DPAPI store, never
parse network/discovery/UI bytes as persisted authority.

Enrollment commits through a persistence callback before the registry returns
the peer. Failed publication revokes candidate clones. Duplicate enrollment does
not revoke an existing grant. Explicit replacement requires a separate newly
confirmed pairing; a clone of existing authority cannot reactivate revocation.
Successful replacement revokes old live clones; failed replacement preserves the
old grant and invalidates the new candidate.

Revocation stops live authority before attempting persistence. A failed write
returns an error, blocks new registry authorizations, and requires a successful
persistence retry. It must never be displayed as successful durable revocation.
Only an acknowledged successful atomic write establishes restart persistence;
power loss before a failed write is retried cannot magically commit it. Generation
numbers do not protect against an administrator restoring an older valid blob.

Six registry tests and a Windows loopback/DPAPI/filesystem integration test cover
restart-style reconstruction, revoked tombstones, identity binding, failures,
replacement/replay and malformed input. The Windows test does not restart a
machine/service or inject input. Production LocalSystem bootstrap still needs
atomic identity/registry lifecycle, authenticated UI pairing and service wiring.

## Atomic pilot identity/registry lifecycle

`inputleap-pilot::secure_state::PersistentSecurityState` combines the private
identity and its identity-bound peer registry in one `ILSEC001` snapshot. The
only active file for this lifecycle is `security-state.dpapi`, with a distinct
DPAPI purpose. Every enrollment/replacement/revocation publishes one encrypted
snapshot, avoiding split identity/peer-file commits. Temporary plaintext bundle
buffers are zeroized and never implement IPC serialization or Debug disclosure.

Explicit `create_new` refuses existing or corrupt state and historical separate
records. Ordinary `open_existing` does not create a missing directory or identity,
rejects mixed historical layouts and validates outer lengths, inner identity
key/certificate consistency and registry binding before returning authority.
There is no recovery by silently making a new key. Provisioning/migration must
be an explicitly authorized service/installer action, not boot fallback.

Four Windows tests cover stable public identity across reopen, startup without
implicit creation, corruption/partial-record refusal, bounded malformed snapshot
headers, and real loopback pairing/enrollment/revocation across DPAPI snapshot
reconstruction. The tests use isolated current-account temporary directories.
The SCM service retains a diagnostic command dispatcher and no productive input,
but now loads this lifecycle as LocalSystem before reporting Running. Explicit
SCM mode `--service-provision` creates a new state and refuses existing identity;
ordinary `--service` opens existing state only. The path comes from the OS
ProgramData known folder, never environment variables or IPC/CLI path input.
Normal startup never provisions or regenerates a missing/corrupt snapshot.

The native SCM smoke installs the separate Manual service in provision mode,
checks authenticated IPC when an interactive session exists, changes its trusted
SCM configuration to ordinary mode and restarts. The snapshot hash must remain
unchanged; Running is published only after successful restore. It checks that
the administrator cannot decrypt SYSTEM ciphertext with the exact purpose
entropy, and a deliberately corrupt synthetic snapshot must stop startup with
an error before Running. Only freshly created, hash-checked test state and exact
known files are removed; pre-existing service/data/install directories cause
refusal. This is not yet authenticated network pairing from Tauri or a Windows
two-machine/reboot/suspend pilot. Such acceptance remains open.
