# Changelog

## 3.7.1-modernized - 2026-08-17

- Made the Tauri application the authenticated controller for the managed Windows runtime.
- Added Tauri start and stop controls and migrated the active runtime away from the legacy persistent task.
- Aligned the Tauri layout file with the runtime configuration used for mouse and keyboard sharing.

## 3.0.13-modernized - 2026-07-10

- Pressing Enter in the client server-IP field now performs the same action as clicking `Aplicar`.
- The entered IP remains saved and the client connection is reapplied immediately.

## 3.0.12-modernized - 2026-07-07

- Enables above-normal process priority for the Windows mouse/keyboard process launched by the GUI.
- Improves responsiveness for cross-machine control on busy systems or Wi-Fi links.

## 3.0.11-modernized - 2026-07-07

- Automatically opens every verified received transfer item, not only quick text and clipboard images.
- Keeps failed SHA-256 transfers from opening automatically.

## 3.0.10-modernized - 2026-07-07

- Removed the incoming transfer confirmation dialog so accepted transfers no longer interrupt the workflow.
- Incoming transfers now start automatically and continue to report progress through status, tray notifications, and history.

## 3.0.9-modernized - 2026-07-07

- Removed the received-file dialog from the normal transfer flow.
- Automatically opens received quick text and clipboard image transfers after SHA-256 verification.

## 3.0.8-modernized - 2026-07-07

- Fixed a Windows GUI crash that could happen after receiving text, clipboard images, files, or folders.
- Changed received-file alerts to non-blocking notifications with buttons to open the received file or folder.

## 3.0.7-modernized - 2026-07-07

- Normalized IPv4-mapped IPv6 addresses like `::ffff:192.0.2.161` to plain IPv4 for file transfers.
- Improved destination detection so transfer tests and error messages use the clearer IPv4 address.

## 3.0.6-modernized - 2026-07-07

- Added in-app release notes through `Ajuda > Novidades da versão`.
- Kept Windows installer metadata aligned with the modernized version.

## 3.0.5-modernized - 2026-07-07

- Added the InputLeap Modernized contributors notice to the About dialog.
- Fixed the About dialog version text so it no longer shows trailing hyphens.

## 3.0.4-modernized - 2026-07-07

- Started modernized versioning for this fork.
- Set the default build version suffix to `modernized`.
- Documented the Windows installer version and SHA-256.

## Earlier Modernized Work

- Modernized Qt UI styling.
- Improved Brazilian Portuguese translations.
- Added cross-platform file, folder, clipboard image, quick text, and test file transfers.
- Added destination selection, transfer preflight checks, queue actions, transfer history, and recent received files.
