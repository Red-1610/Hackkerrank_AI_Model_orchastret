# HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
## AI-Powered Deletion-Audit Agent

This repository contains the complete, production-ready solution for the **HackerRank Orchestrate: Ghost Data Still Exists** challenge.

The system performs automated, evidence-grounded deletion audits across a distributed commerce architecture. For each request, the agent establishes whether the subject actually requested erasure, reconstructs current and historical identifiers bounded by `audit_at`, searches heterogeneous evidence across distributed services, applies `deletion_rules.csv`, and produces an audit verdict (`COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`) accompanied by an ordered array of findings, remediations, and verification checks.

---

## 1. Approach Overview

The audit pipeline is structured into four decoupled, deterministic stages:

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ 1. Unified Evidence     │ ──> │ 2. Temporal Identity    │ ──> │ 3. Policy & Grounded    │ ──> │ 4. Triadic Ordering &   │
│    Indexer              │     │    Resolver             │     │    Audit Engine         │     │    JSON Serialization   │
│ (code/parse_evidence.py)│     │ (code/pipeline.py)      │     │ (code/pipeline.py)      │     │ (code/main.py)          │
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
```

### 1.1 Unified Evidence Indexer (`code/parse_evidence.py`)
Parses and normalizes **1,853 evidence artifacts** across distributed storage formats into unified in-memory records:
- **SQLite Database Snapshots**: Primary, read replica, reporting replica, and failover replicas executed via Python's built-in `sqlite3` in `:memory:` with custom SQL function shims (`json_valid`).
- **Support Attachments (PDFs & Documents)**: Extracted via system Poppler utilities (`pdftotext`) to recover invoice addresses, support ticket communications, and refund requests.
- **Structured JSON Records**: Full snapshot bundles (`customer_data_snapshot_bundle_*.json`), single-service exports (`customer_analytics_report_*.json`, `security_audit_ledger_*.json`), and account handover manifests.
- **Multi-Format Application Logs**: Unified parser processing JSON Lines (`structured_service_events_*.log`), bracket-delimited distributed traces (`application_trace_*.log`), and key-value syslog streams with ISO timestamp bounding.

### 1.2 Temporal Identity & Intent Resolution (`code/pipeline.py`)
- **Intent Disambiguation**: Distinguishes true erasure authorizations from non-deletion requests (access, login recovery, profile keep requests, or marketing-only opt-outs) per §6.5, assigning `NOT_APPLICABLE` and `steps_json: []`.
- **Temporal Identity Bounding**: Recovers user identity sets (current email, phone, name, email hash) and historical transitions from `user_audit_log.csv` strictly enforced at `event_time <= audit_at`. Post-cutoff identity changes never leak into the subject bundle.

### 1.3 Grounded Audit & FIFO Resource Allocation
- **Evidence-Backed Verification**: Reported workflow statuses (`reported_status`) and operation results are treated as unverified claims. True state is established solely from participant-visible evidence captured at or before `audit_at`.
- **Tombstone Policy Handling**: Correctly handles account tombstones (`identity_service`) by ensuring direct identifiers (name, email, phone, hash) are stripped via `REDACT_RECORD` while preserving internal subject references.
- **Stateful FIFO Account Allocation**: Resolves primary account resources and analytics profiles from `deletion_worker` events in `system_activity.csv` using strict FIFO queues and evidence reservations (`used_accounts`, `used_analytics`), eliminating cross-request collisions during concurrent request batches.

### 1.4 Triadic Remediation & Verification Sequencing
Sorts and serializes steps using a strict semantic ranker `(PHASE_RANK, OP_RANK, SYSTEM_ID, RESOURCE_ID)`:
1. **FINDING**: Emits policy violations (`REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`, `REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`) citing the proving `evidence_id`.
2. **REMEDIATION**: Generates dependency-ordered remediation actions. Data flows are disabled (`DISABLE_DATA_FLOW`) and restores blocked (`BLOCK_RESTORE`) *before* records are deleted (`DELETE_RECORD`), redacted (`REDACT_RECORD`), or anonymized (`ANONYMIZE_RECORD`). All proposed remediation steps use an empty `evidence_id` (`""`).
3. **VERIFICATION**: Formulates post-remediation verification checks for all affected resources (`evidence_id: ""`). For `COMPLETE` cases, emits evidence-backed checks proving the compliant state at `audit_at`.

---

## 2. Setup & Environment Instructions

### Requirements
- **Operating System**: Linux, macOS, or Windows
- **Python**: Version 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.14)
- **Dependencies**:
  - `pandas`
  - Standard library: `sqlite3`, `json`, `re`, `pathlib`, `glob`, `dataclasses`, `subprocess`
  - System utility: `poppler-utils` (`pdftotext` for PDF attachment extraction, pre-installed in Linux environments)

### Installation
Clone or navigate to the repository root:

```bash
cd hackerrank-orchestrate-october26
pip install pandas
```

---

## 3. Execution Instructions

### Run the Full Audit Pipeline (All 518 Requests)
To execute the end-to-end deletion audit on all 518 cases in `dataset/deletion_requests.csv` and generate `output.csv` at the repository root:

```bash
python3 code/main.py
```

- **Execution Time**: ~3.1 seconds for all 518 requests.
- **Output Generated**: `output.csv` at the repository root with exactly 518 data rows sorted by `case_id`.

### Run Benchmark on Sample Dataset (32 Public Requests)
To verify the audit pipeline against the 32 public cases in `dataset/sample_deletion_requests.csv`:

```bash
python3 code/main.py --sample
```

---

## 4. Benchmark Accuracy & Evaluation Summary

Evaluated against the official public ground truth (`dataset/sample_output.csv`):

| Evaluation Dimension | Benchmark Metric | Result |
| :--- | :--- | :---: |
| **Case-Level Status** | Deletion Status Accuracy | **32 / 32 (100.0%)** |
| **Sequence Fidelity** | Exact Sequence Match (Parsed JSON) | **31 / 32 (96.88%)** |
| **Step Attributes** | `step_no` Accuracy | **193 / 193 (100.0%)** |
| **Phase Adherence** | `phase` Order Accuracy | **193 / 193 (100.0%)** |
| **System Grounding** | `system_id` Accuracy | **193 / 193 (100.0%)** |
| **Operations** | `operation` Accuracy | **193 / 193 (100.0%)** |
| **State Mapping** | `state` Accuracy | **193 / 193 (100.0%)** |
| **Evidence Citations** | `evidence_id` Accuracy | **193 / 193 (100.0%)** |
| **Resource Resolution** | `resource_id` Accuracy | **192 / 193 (99.48%)** |

Comprehensive reports are available at:
- [`evaluation/evaluation_report.md`](./evaluation/evaluation_report.md): Case accuracy, step-level metrics, 3 custom test cases with edge scenarios, and failure analysis.
- [`evaluation/usage_report.md`](./evaluation/usage_report.md): Token volume, model providers (`Google Gemini`), call counts, and unit economic analysis ($0.0000397 per audited request).

---

## 5. Submission Artifacts

| HackerRank Slot | Artifact File | Description |
| :--- | :--- | :--- |
| **Source code - your complete working project** | **`code.zip`** | Runnable solution (`code/`), `README.md`, and `evaluation/` reports |
| **Output file** | **`output.csv`** | 518 prediction rows strictly formatted per §6.3 |
| **Chat transcript** | **`log.txt`** | Full conversation turn history logged per AGENTS.md §5 |

### Challenge & Submission Link
https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists
