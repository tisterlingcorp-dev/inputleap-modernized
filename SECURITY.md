# Security Policy

## Supported versions

InputLeap Modernized is an experimental fork. Security fixes are applied to the current `master` branch. No released binary channel is currently supported.

The production input-sharing path requires TLS/mTLS. Reports that rely on disabling transport security are outside the supported configuration.

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](https://github.com/tisterlingcorp-dev/inputleap-modernized/security/advisories/new). Do not open a public issue for a suspected vulnerability before coordinated disclosure.

Include the affected revision, operating system, reproducible steps and the security impact. Redact private keys, certificates containing private keys, credentials, hostnames, user names, IP addresses, local paths and runtime logs before attaching evidence.

You should receive an initial acknowledgement within seven days. A fix or disclosure date depends on severity, reproducibility and upstream coordination requirements.

## Update and release trust

Source availability, a checksum and HTTPS are not sufficient to authenticate an application update. Production update artifacts must pass the repository's signed-manifest threshold, package digest, Authenticode publisher, anti-replay and rollback checks before installation.
