# Secure update manifest signing

InputLeap stable update manifests use a 2-of-3 Ed25519 policy. Each private key is a separate Windows DPAPI artifact and **must be held by a different custodian on a different Windows user or machine**. No command loads more than one private key.

## Key initialization

Run once on each custodian workstation, substituting that custodian's assigned production key ID:

```text
python tools/update_manifest.py init --key <custodian-key.dpapi> --key-id <production-key-id>
```

The command refuses every established production ID, so production keys cannot be silently recreated. Initial production enrollment requires a separately reviewed bootstrap procedure; never copy a DPAPI key file to another custodian.

## Produce one contribution

Each custodian receives the exact same final package and release fields, verifies them out of band, and runs:

```text
python tools/update_manifest.py sign-contribution \
  --signer <production-key-id>=<custodian-key.dpapi> \
  --package <final-package> \
  --package-url <https-package-url> \
  --version <major.minor.patch> \
  --issued <YYYY-MM-DDTHH:MM:SSZ> \
  --expires <YYYY-MM-DDTHH:MM:SSZ> \
  --notes <plain-text-release-notes> \
  --output <custodian-contribution.json>
```

Package size and SHA-256 are computed from one open descriptor. The signer rejects the operation if size, timestamps, file identity, or path identity changes during hashing. A contribution contains only the canonical payload, its digest, key ID, and signature; it contains no private material.

Transfer only the contribution JSON to the assembler. Do not transfer keys, decrypted seeds, Credential Manager exports, or custodian profiles.

## Assemble the threshold manifest

The assembler needs no private key and may run on a separate machine:

```text
python tools/update_manifest.py assemble \
  --contribution <custodian-a.json> \
  --contribution <custodian-b.json> \
  --output <stable-manifest.json>
```

Assembly fails closed unless at least two distinct pinned production keys signed byte-identical payloads. Every contribution is required to be canonical and is independently verified before the schema-2 envelope is written atomically.

## Rotation and loss

All three production anchors are active during the normal overlap window. Therefore loss or revocation of one custodian still leaves two independent active keys. Revoke a suspected key in the client trust policy before using the remaining custodians to publish another manifest. Never lower the client threshold to recover availability.

## Mandatory release checks

1. Freeze and hash the final package before distributing it to custodians.
2. Compare the package hash and every release field over an independent channel.
3. Produce contributions in separate custody domains.
4. Assemble and independently verify the resulting schema-2 manifest.
5. Run the C++ verifier fixture tests and the Python signer tests.
6. Publish only in the release/public-feed phase; signing alone never authorizes publication.
