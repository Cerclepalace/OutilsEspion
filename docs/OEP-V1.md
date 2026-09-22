# OEP v1 — OutilsEspion Evidence Package

## Purpose

OEP v1 is the portable exchange contract between the Windows collector, deterministic analysis pipeline, mobile client, and optional LLM analysis layer.

## Security boundary

```text
RAW EVIDENCE -> HASH -> ANALYSIS -> CLASSIFICATION -> VALIDATION
```

Raw evidence is immutable by policy. Analysis is derived data. The LLM may interpret supplied evidence and findings, but does not gain permission to modify raw evidence or perform remediation.

`UNKNOWN` is not `MALICIOUS`.

## Package layout

```text
OEP-v1/
├── manifest.json
├── evidence/
├── analysis/
├── timeline/
├── graph/
├── risk/
├── controls/
├── final/
└── integrity/
```

## Current OutilsEspion mapping

| Pipeline | Current output | OEP destination |
|---|---|---|
| P001 | `raw/inventory.json` + `manifest.json` | `evidence/` + package manifest |
| P002 | `detections.json` | `analysis/detections` |
| P003 | `correlations.json` | `analysis/correlations` |
| P004 | `classification.json` | `analysis/classifications` |
| P005 | `falsification.json` | `analysis/falsification` |
| P006 | `timeline.json` | `timeline/` |
| P007 | `graph.json` | `graph/` |
| P008 | `risk.json` | `risk/` |
| P009 | `controls.json` | `controls/` |
| P010 | `final.json` | `final/` |

This mapping is an interoperability target. The existing scripts are not yet OEP-native.

## Evidence identity

Every raw record uses a stable `evidence_id`. Derived objects reference evidence through `evidence_refs`.

No finding should exist without provenance to one or more evidence records.

## Classification

OEP v1 permits:

- `BENIGN`
- `UNKNOWN`
- `SUSPICIOUS`
- `HIGH_RISK`

Classification is not equivalent to proof of compromise. Confidence is represented separately.

## Risk

Risk keeps `impact` and `likelihood` separate. `UNKNOWN` is a valid value. The schema intentionally does not require a numeric risk score.

## Controls

Controls are recommendations or validation requirements. `authorization_required` is true in v1 and `NO_AUTOMATIC_REMEDIATION` remains the mutation policy.

## Integrity

The package uses SHA-256 file hashes. A consumer must be able to verify the package before trusting derived content.

## Mobile contract

A mobile implementation needs only to:

1. import an OEP package;
2. verify integrity;
3. parse evidence and derived objects;
4. resolve references;
5. render findings, timeline and graph;
6. optionally pass selected structured data to an LLM;
7. preserve the distinction between evidence, analysis and interpretation.

The mobile client does not need to execute the Windows PowerShell collector.

## OEP-001 validation gates

- schema version is explicit;
- raw evidence is separate from derived analysis;
- every finding has evidence provenance;
- SHA-256 is verifiable;
- `UNKNOWN` is preserved as a distinct state;
- no conclusion is accepted without provenance;
- package can be consumed offline;
- package is portable to mobile;
- LLM input is read-only with respect to evidence;
- no automatic remediation is represented by the contract.
