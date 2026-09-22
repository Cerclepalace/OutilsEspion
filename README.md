# OutilsEspion — Portable Offline Windows Security Audit

Defensive, read-only Windows audit designed for removable media. The project is intentionally **non-persistent**, **offline-first**, and **evidence-driven**.

## Design targets

- USB package target: <= 8 GB
- First operational collection target: ~10 seconds (benchmark, not a guarantee)
- No Internet, DNS, cloud, API, telemetry, download, or update dependency
- No service, scheduled task, Run key, or other persistence created by the tool
- Raw evidence retained separately from analysis
- SHA-256 hashes for collected artifacts
- Local encrypted evidence container using AES-256-GCM when supported
- User-supplied passphrase; no embedded master key
- No automatic deletion or remediation

## Security model

`RAW EVIDENCE -> HASH -> ANALYSIS -> CLASSIFICATION -> VALIDATION`

`UNKNOWN` is not `MALICIOUS`. A suspicious indicator is not a compromise finding without corroboration.

## Run

Use PowerShell 7+ for the encrypted evidence path:

```powershell
pwsh -ExecutionPolicy Bypass -File .\src\Invoke-OutilsEspion.ps1
```

The script performs local collection only. It does not remove software or alter persistence.

## Scope

The collector covers system identity, processes, services, scheduled tasks, startup entries, IFEO, Winlogon, AppInit, WMI persistence metadata, Defender exclusions/status, proxy/hosts configuration, active network connections, and targeted executable hashes/signatures.

## Validation gates

A release is VALIDATED only after:

1. offline execution test;
2. network non-communication test;
3. non-persistence before/after test;
4. evidence integrity verification;
5. encryption/decryption round-trip test;
6. USB size measurement;
7. startup benchmark;
8. clean-machine false-positive test.

Until those tests are documented, status remains `NOT VALIDATED`.
