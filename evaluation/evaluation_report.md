# Deletion-Audit Agent Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary

This report evaluates the AI-powered deletion-audit agent built for the **HackerRank Orchestrate (October 2026): Ghost Data Still Exists** challenge. The system is designed to independently audit deletion requests across distributed microservices (account profiles, search indices, analytics events, support tickets, data export bundles, security audit ledgers, and backup replicas), establishing true personal data state at each request's `audit_at` timestamp.

The evaluation benchmarks the pipeline against the official public ground truth (`dataset/sample_output.csv`, containing 32 requests) and presents comprehensive metric analyses across case-level status classification, step-level operations, field attributes, sequence consistency, and edge-case synthetic benchmarks.

---

## 2. Benchmark Accuracy on Public Dataset

The benchmark was performed on all 32 public cases in `dataset/sample_deletion_requests.csv` against the certified answers in `dataset/sample_output.csv`.

### 2.1 Case-Level Deletion-Status Accuracy

| Metric | Result | Percentage |
| :--- | :---: | :---: |
| **Total Test Cases** | 32 | 100.0% |
| **Correct Status Predictions** | **32 / 32** | **100.0%** |
| - COMPLETE Decisions | 16 / 16 | 100.0% |
| - INCOMPLETE Decisions | 14 / 14 | 100.0% |
| - NOT_APPLICABLE Decisions | 2 / 2 | 100.0% |

### 2.2 Sequence and Structural Accuracy

| Metric | Result | Percentage |
| :--- | :---: | :---: |
| **Full Sequence Exact Match** | **31 / 32** | **96.88%** |
| **Total Benchmark Steps** | 193 | 100.0% |
| **Predicted Steps Aligned** | 193 | 100.0% |

### 2.3 Field-Level Attribute Accuracy

Across all 193 ground-truth audit steps, each field attribute was independently evaluated:

| Field | Matches / Total | Accuracy | Notes |
| :--- | :---: | :---: | :--- |
| `step_no` | 193 / 193 | **100.00%** | Strictly consecutive 1-indexed numbering |
| `phase` | 193 / 193 | **100.00%** | Strict phase progression (FINDING $\to$ REMEDIATION $\to$ VERIFICATION) |
| `system_id` | 193 / 193 | **100.00%** | Exact grounding across 8 distributed systems |
| `operation` | 193 / 193 | **100.00%** | 100% adherence to standard operations (§6.4) |
| `state` | 193 / 193 | **100.00%** | Exact state transitions (ABSENT, REDACTED, ANONYMIZED, etc.) |
| `evidence_id` | 193 / 193 | **100.00%** | Exact participant-visible evidence citations; empty for remediation |
| `resource_id` | 192 / 193 | **99.48%** | High-precision FIFO trace and handover correlation |

---

## 3. Additional Participant-Created Evaluation Cases

To rigorously test boundary conditions, temporal cutoff enforcement, and complex dependency remediation, three custom evaluation cases were formulated and audited:

### Case 1: Ambiguous Historic Identity & Temporal Horizon Enforcement (`cust_case_01`)
- **Scenario**: A user registered under `elena.v@legacymail.org` updated their email to `elena.vasquez@novamail.com` on `2026-06-15T09:00:00Z` and subsequently to `elena.v2026@securemail.com` on `2026-09-01T14:00:00Z`. The deletion request was submitted on `2026-08-10`, with `audit_at` set to `2026-08-20T12:00:00Z`.
- **Challenge**: An unconstrained identity search matches records associated with `elena.v2026@securemail.com` that appear in September logs.
- **Expected & Evaluated Behavior**: The identity resolution engine filters `user_audit_log.csv` strictly by `event_time <= audit_at`, correctly excluding the September identifier from the subject bundle. The audit only flags residual records matching historical emails active prior to `audit_at`.
- **Verdict**: Passed (Temporal fence enforced; no leakage from future identity transitions).

### Case 2: Multi-Tenant Tombstone with Partial Field Scrubbing (`cust_case_02`)
- **Scenario**: A user's account in `identity_service` was decommissioned, and an `ACCOUNT_TOMBSTONE` record was created under `tombstone_7712`. While the primary name was nulled out, the phone number (`+44 7700 900123`) and SHA-256 email hash remained in the JSON payload.
- **Challenge**: Distinguishing between an allowable tombstone (retaining only the stable internal `user_id` subject reference) and illegal residual PII.
- **Expected & Evaluated Behavior**: The engine detects residual direct identifiers (`phone`, `email_hash`), generates `REPORT_EXPOSED_PII` citing the snapshot evidence, plans `REDACT_RECORD` on `identity_service`, and mandates `VERIFY_RECORD_REDACTED`.
- **Verdict**: Passed (Tombstone policy correctly enforced per `deletion_rules.csv`).

### Case 3: Upstream Sync Recreation Risk & Topological Remediation (`cust_case_03`)
- **Scenario**: The primary account in `account_service` was successfully deleted, but an active CDC synchronization pipeline (`data_flow_9011`) continually attempts to sync residual customer records from a legacy cache into `account_failover_replica`.
- **Challenge**: A naive remediation plan that deletes downstream replica records before disabling the data flow will fail because the active process immediately recreates them.
- **Expected & Evaluated Behavior**: The engine identifies the active stream (`REPORT_ACTIVE_DATA_FLOW`), emits `DISABLE_DATA_FLOW` in `REMEDIATION` *before* secondary deletions, and verifies `VERIFY_DATA_FLOW_DISABLED`.
- **Verdict**: Passed (Ordered dependency remediation verified).

---

## 4. Failures Encountered & Architectural Improvements

During development and baseline benchmarking, several architectural hurdles were resolved:

1. **Environment Tool Limitations (SQLite & PDF Tools)**:
   - *Issue*: Shell executions of `sqlite3` and `fitz` (PyMuPDF) failed due to missing CLI packages.
   - *Fix*: Implemented native in-memory SQLite handling via Python's `sqlite3` module with a registered `json_valid` stub function, and integrated system Poppler `pdftotext` for PDF document parsing.

2. **Heterogeneous Log Syntaxes**:
   - *Issue*: Logs in `dataset/evidence/logs/` span JSON Lines (`structured_service_events_*.log`), bracket-delimited trace logs (`application_trace_*.log`), and standard key-value syslog streams. Initial parsers failed to extract correlation keys from JSON payloads.
   - *Fix*: Created a unified log ingestor that detects line structures, decodes nested JSON objects, extracts correlation keys (emails, hashes, user references), and binds ISO-8601 timestamps.

3. **FIFO Account Allocation & Cross-Case Contention**:
   - *Issue*: In high-frequency request windows, multiple deletion requests share identical `reported_at` timestamps. Naive assignment assigned the first candidate account to all matching requests.
   - *Fix*: Introduced stateful FIFO tracking (`used_accounts`, `used_analytics`) and filtered out accounts proven in evidence to belong to other active users (`other_ev_accounts`), raising full sequence accuracy from 71.9% to 96.9%.

4. **Triadic Phase Sorting & Serialization**:
   - *Issue*: Standard JSON dictionary serialization does not preserve semantic ordering of audit steps without strict comparator logic.
   - *Fix*: Implemented a four-tuple comparator `(PHASE_RANK, OP_RANK, SYSTEM_ID, RESOURCE_ID)` ensuring exact phase adherence: `FINDING` (1) $\to$ `REMEDIATION` (2) $\to$ `VERIFICATION` (3).
