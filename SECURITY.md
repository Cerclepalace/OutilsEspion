# Security Model

## Purpose

OutilsEspion is a defensive Windows audit collector. It is not a stealth implant and does not provide persistence, covert surveillance, credential theft, or remote control.

## Evidence

Collected artifacts are hashed with SHA-256. The collector is read-only with respect to the target system's security configuration.

## Encryption

When PowerShell 7+ and the platform's `AesGcm` implementation are available, the manifest is encrypted locally with AES-256-GCM. A 32-byte key is derived from a user-supplied passphrase using PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 128-bit salt. The passphrase and derived key are not written to disk.

This protects confidentiality of the manifest at rest, but it is not a substitute for full disk encryption or a separately managed evidence key. Raw evidence files remain local and should be stored on encrypted removable media or inside an encrypted evidence container in the next hardening phase.

## Network

The tool has no network client, downloader, cloud endpoint, telemetry endpoint, or update mechanism. Network state is collected as evidence only.

## Validation status

`NOT VALIDATED` until offline, no-network, non-persistence, cryptographic round-trip, integrity, size, performance, and false-positive tests are executed and recorded.
