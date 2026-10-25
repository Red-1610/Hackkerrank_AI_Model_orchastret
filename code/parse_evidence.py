import os
import re
import json
import sqlite3
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent if Path(__file__).resolve().parent.name == "code" else Path(__file__).resolve().parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"

@dataclass
class EvidenceRecord:
    evidence_id: str
    captured_at: pd.Timestamp
    system_id: str
    resource_id: str
    status_type: str  # REMAINING, EXPOSED_PII, ACTIVE_FLOW, RESTORE_RISK, ABSENT, REDACTED, ANONYMIZED, DISABLED, BLOCKED, PRESENT
    keys: Set[str] = field(default_factory=set)

class EvidenceIndexer:
    def __init__(self):
        self.evidence_files = pd.read_csv(DATASET_DIR / "evidence_files.csv")
        self.evidence_files["captured_at_dt"] = pd.to_datetime(self.evidence_files["captured_at"], utc=True)
        self.records: List[EvidenceRecord] = []
        self._index_all()

    def _add_record(self, ev_id: str, cap_at: pd.Timestamp, sys_id: str, res_id: str, status_type: str, keys: Set[str]):
        clean_keys = set()
        for k in keys:
            if k and pd.notna(k):
                s = str(k).strip().strip('"').strip("'")
                if s and s.lower() not in ["null", "none"]:
                    clean_keys.add(s.lower())
        if clean_keys:
            self.records.append(EvidenceRecord(
                evidence_id=ev_id,
                captured_at=cap_at,
                system_id=sys_id,
                resource_id=res_id,
                status_type=status_type,
                keys=clean_keys,
            ))

    def _index_all(self):
        # 1. service_resource_export_*.json
        for f in sorted((EVIDENCE_DIR / "records").glob("service_resource_export_*.json")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp: data = json.load(fp)
            s_exp = data.get("service_exports", {})

            for item in s_exp.get("account_service", {}).get("profile_lookups", []):
                res_id = item["resource_id"]
                keys = set()
                prof = item.get("profile") or {}
                if prof.get("email"): keys.add(prof["email"])
                if prof.get("customer_reference"): keys.add(prof["customer_reference"])
                status = "ABSENT" if item.get("status_code") == 404 else "REMAINING"
                self._add_record(ev_id, cap_at, "account_service", res_id, status, keys)

            for item in s_exp.get("search_service", {}).get("index_queries", []):
                res_id = item["resource_id"]
                keys = {item.get("query")}
                hits = item.get("hits", {}).get("documents", [])
                for doc in hits:
                    if doc.get("email"): keys.add(doc["email"])
                    if doc.get("customer_reference"): keys.add(doc["customer_reference"])
                status = "REMAINING" if hits else "ABSENT"
                self._add_record(ev_id, cap_at, "search_service", res_id, status, keys)

            for item in s_exp.get("support_platform", {}).get("tickets", []):
                res_id = item["resource_id"]
                keys = set()
                if item.get("customer_reference"): keys.add(item["customer_reference"])
                if item.get("requester_email"): keys.add(item["requester_email"])
                has_pii = bool(item.get("requester_email") or item.get("requester_name") or item.get("requester_phone"))
                status = "EXPOSED_PII" if has_pii else "REDACTED"
                self._add_record(ev_id, cap_at, "support_platform", res_id, status, keys)

            for item in s_exp.get("analytics_platform", {}).get("profiles", []):
                res_id = item["resource_id"]
                keys = set()
                if item.get("customer_reference"): keys.add(item["customer_reference"])
                if item.get("email"): keys.add(item["email"])
                if item.get("phone"): keys.add(item["phone"])
                has_pii = bool(item.get("email") or item.get("phone") or item.get("customer_reference"))
                status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                self._add_record(ev_id, cap_at, "analytics_platform", res_id, status, keys)

            for item in s_exp.get("integration_service", {}).get("connectors", []):
                res_id = item["resource_id"]
                keys = set()
                if item.get("customer_reference"): keys.add(item["customer_reference"])
                if item.get("customer_email"): keys.add(item["customer_email"])
                status = "ACTIVE_FLOW" if item.get("enabled") else "DISABLED"
                self._add_record(ev_id, cap_at, "integration_service", res_id, status, keys)

            for item in s_exp.get("backup_service", {}).get("restore_entries", []):
                res_id = item["resource_id"]
                keys = set()
                if item.get("customer_reference"): keys.add(item["customer_reference"])
                if item.get("customer_email"): keys.add(item["customer_email"])
                status = "RESTORE_RISK" if item.get("restore_allowed") else "BLOCKED"
                self._add_record(ev_id, cap_at, "backup_service", res_id, status, keys)

            for item in s_exp.get("security_service", {}).get("audit_records", []):
                res_id = item["resource_id"]
                keys = {item.get("subject_reference")}
                self._add_record(ev_id, cap_at, "security_service", res_id, "PRESENT", keys)

            for item in s_exp.get("export_service", {}).get("exports", []):
                res_id = item["resource_id"]
                keys = set()
                if item.get("customer_reference"): keys.add(item["customer_reference"])
                if item.get("owner_email"): keys.add(item["owner_email"])
                self._add_record(ev_id, cap_at, "export_service", res_id, "REMAINING", keys)

        # 2. customer_data_snapshot_bundle_*.json
        for f in sorted((EVIDENCE_DIR / "records").glob("customer_data_snapshot_bundle_*.json")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp: data = json.load(fp)
            for sn in data.get("snapshots", []):
                coll = sn.get("collection", "")
                records = sn.get("records", [])

                if coll == "customer_profiles":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("email"), r.get("user_id"), r.get("customer_reference")}
                        self._add_record(ev_id, cap_at, "account_service", res_id, "REMAINING", keys)
                elif coll == "deleted_customer_references":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("subject_reference"), r.get("email")}
                        has_pii = bool(r.get("name") or r.get("email") or r.get("phone") or r.get("email_hash"))
                        status = "EXPOSED_PII" if has_pii else "REDACTED"
                        self._add_record(ev_id, cap_at, "identity_service", res_id, status, keys)
                elif coll == "security_audit_events":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("subject_reference")}
                        self._add_record(ev_id, cap_at, "security_service", res_id, "PRESENT", keys)
                elif coll == "customer_search_documents":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("email"), r.get("customer_reference")}
                        self._add_record(ev_id, cap_at, "search_service", res_id, "REMAINING", keys)
                elif coll == "customer_analytics_reports":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("email"), r.get("user_id")}
                        has_pii = bool(r.get("email") or r.get("phone") or r.get("user_id"))
                        status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                        self._add_record(ev_id, cap_at, "analytics_platform", res_id, status, keys)
                elif coll == "backup_catalog":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("subject_reference"), r.get("customer_email")}
                        status = "RESTORE_RISK" if r.get("restore_allowed") else "BLOCKED"
                        self._add_record(ev_id, cap_at, "backup_service", res_id, status, keys)
                elif coll == "connector_configurations":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("subject_reference"), r.get("subject_selector"), r.get("customer_email")}
                        status = "ACTIVE_FLOW" if r.get("enabled") else "DISABLED"
                        self._add_record(ev_id, cap_at, "integration_service", res_id, status, keys)
                elif coll == "support_conversations":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("customer_reference"), r.get("requester_email")}
                        has_pii = bool(r.get("requester_email") or r.get("requester_name") or r.get("requester_phone"))
                        status = "EXPOSED_PII" if has_pii else "REDACTED"
                        self._add_record(ev_id, cap_at, "support_platform", res_id, status, keys)
                elif coll == "ticket_attachments":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("customer_reference"), r.get("requester_email")}
                        self._add_record(ev_id, cap_at, "support_platform", res_id, "REMAINING", keys)
                elif coll == "customer_export_jobs":
                    for r in records:
                        res_id = r["resource_id"]
                        keys = {r.get("owner_email"), r.get("customer_reference")}
                        self._add_record(ev_id, cap_at, "export_service", res_id, "REMAINING", keys)

        # 3. customer_data_inventory_*.sql
        for f in sorted((EVIDENCE_DIR / "databases").glob("customer_data_inventory_*.sql")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            con = sqlite3.connect(":memory:")
            con.create_function("json_valid", 1, lambda x: True)
            with open(f) as fp: con.executescript(fp.read())

            for r in con.execute("SELECT resource_id, customer_reference, email, phone FROM customer_profiles").fetchall():
                self._add_record(ev_id, cap_at, "account_service", r[0], "REMAINING", {r[1], r[2], r[3]})
            for r in con.execute("SELECT resource_id, customer_reference, email, phone FROM customer_search_documents").fetchall():
                self._add_record(ev_id, cap_at, "search_service", r[0], "REMAINING", {r[1], r[2], r[3]})
            for r in con.execute("SELECT resource_id, customer_reference, email, phone FROM customer_analytics_profiles").fetchall():
                has_pii = bool(r[1] or r[2] or r[3])
                status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                self._add_record(ev_id, cap_at, "analytics_platform", r[0], status, {r[1], r[2], r[3]})
            for r in con.execute("SELECT resource_id, customer_reference, requester_email, requester_phone FROM support_records").fetchall():
                has_pii = bool(r[2] or r[3])
                status = "EXPOSED_PII" if has_pii else "REDACTED"
                self._add_record(ev_id, cap_at, "support_platform", r[0], status, {r[1], r[2], r[3]})
            for r in con.execute("SELECT resource_id, customer_reference, owner_email, owner_phone FROM customer_exports").fetchall():
                self._add_record(ev_id, cap_at, "export_service", r[0], "REMAINING", {r[1], r[2], r[3]})
            for r in con.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions").fetchall():
                status = "ACTIVE_FLOW" if r[3] else "DISABLED"
                self._add_record(ev_id, cap_at, "integration_service", r[0], status, {r[1], r[2]})
            for r in con.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries").fetchall():
                status = "RESTORE_RISK" if r[3] else "BLOCKED"
                self._add_record(ev_id, cap_at, "backup_service", r[0], status, {r[1], r[2]})
            for r in con.execute("SELECT resource_id, subject_reference FROM security_audit_records").fetchall():
                self._add_record(ev_id, cap_at, "security_service", r[0], "PRESENT", {r[1]})

        # 4. customer_data_read_replica_*.sql, regional, reporting, failover
        for pattern in ["customer_data_read_replica_*.sql", "customer_data_regional_replicas_*.sql", "customer_data_reporting_replica_*.sql", "customer_data_failover_replica_*.sql"]:
            for f in sorted((EVIDENCE_DIR / "databases").glob(pattern)):
                ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
                if ev_row.empty: continue
                ev_id = ev_row.iloc[0]["file_id"]
                cap_at = ev_row.iloc[0]["captured_at_dt"]
                con = sqlite3.connect(":memory:")
                con.create_function("json_valid", 1, lambda x: True)
                try:
                    with open(f) as fp: con.executescript(fp.read())
                    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                    for table_name in tables:
                        try:
                            for r in con.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {table_name}").fetchall():
                                res_id, origin, coll, r_json = r
                                doc = json.loads(r_json)
                                keys = set()
                                for k_name in ["user_id", "email", "phone", "subject_reference", "subject_selector", "customer_reference", "owner_email", "requester_email"]:
                                    if doc.get(k_name): keys.add(doc[k_name])
                                if isinstance(doc.get("document"), dict):
                                    for k_name in ["email", "customer_reference", "display_name"]:
                                        if doc["document"].get(k_name): keys.add(doc["document"][k_name])

                                if origin == "account_service":
                                    self._add_record(ev_id, cap_at, origin, res_id, "REMAINING", keys)
                                elif origin == "search_service":
                                    self._add_record(ev_id, cap_at, origin, res_id, "REMAINING", keys)
                                elif origin == "analytics_platform":
                                    has_pii = bool(doc.get("email") or doc.get("phone") or doc.get("user_id"))
                                    status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                                    self._add_record(ev_id, cap_at, origin, res_id, status, keys)
                                elif origin == "security_service":
                                    self._add_record(ev_id, cap_at, origin, res_id, "PRESENT", keys)
                                elif origin == "integration_service":
                                    status = "ACTIVE_FLOW" if doc.get("enabled") else "DISABLED"
                                    self._add_record(ev_id, cap_at, origin, res_id, status, keys)
                                elif origin == "backup_service":
                                    status = "RESTORE_RISK" if doc.get("restore_allowed") else "BLOCKED"
                                    self._add_record(ev_id, cap_at, origin, res_id, status, keys)
                                elif origin == "support_platform":
                                    has_pii = bool(doc.get("email") or doc.get("phone") or doc.get("requester_email") or doc.get("customer_reference"))
                                    status = "EXPOSED_PII" if has_pii else "REDACTED"
                                    self._add_record(ev_id, cap_at, origin, res_id, status, keys)
                        except Exception:
                            pass
                except Exception:
                    pass

        # 5. customer_accounts_failover_replica_*.sql
        for f in sorted((EVIDENCE_DIR / "databases").glob("customer_accounts_failover_replica_*.sql")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            con = sqlite3.connect(":memory:")
            con.create_function("json_valid", 1, lambda x: True)
            with open(f) as fp: con.executescript(fp.read())
            for r in con.execute("SELECT resource_id, user_id, email, phone FROM customer_profiles_failover_replica").fetchall():
                self._add_record(ev_id, cap_at, "account_service", r[0], "REMAINING", {r[1], r[2], r[3]})

        # 6. customer_search_primary_*.sql
        for f in sorted((EVIDENCE_DIR / "databases").glob("customer_search_primary_*.sql")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            con = sqlite3.connect(":memory:")
            con.create_function("json_valid", 1, lambda x: True)
            with open(f) as fp: con.executescript(fp.read())
            for r in con.execute("SELECT resource_id, display_name, email, source_resource_id FROM search_documents_primary").fetchall():
                self._add_record(ev_id, cap_at, "search_service", r[0], "REMAINING", {r[1], r[2]})

        # 7. customer_account_handover_*.txt
        for f in sorted((EVIDENCE_DIR / "records").glob("customer_account_handover_*.txt")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp:
                for line in fp:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 6:
                        sys_id = parts[1]
                        res_id = parts[2]
                        raw_status = parts[4]
                        key = parts[5]

                        if raw_status == "NOT_FOUND":
                            status = "ABSENT"
                        elif raw_status == "FOUND":
                            status = "REMAINING" if sys_id != "security_service" else "PRESENT"
                        elif raw_status == "IDENTIFIABLE":
                            status = "EXPOSED_PII"
                        elif raw_status == "ANONYMIZED":
                            status = "ANONYMIZED"
                        elif raw_status == "REDACTED":
                            status = "REDACTED"
                        elif raw_status == "ACTIVE":
                            status = "ACTIVE_FLOW" if sys_id == "integration_service" else "RESTORE_RISK"
                        elif raw_status == "DISABLED":
                            status = "DISABLED"
                        elif raw_status == "BLOCKED":
                            status = "BLOCKED"
                        else:
                            status = raw_status

                        self._add_record(ev_id, cap_at, sys_id, res_id, status, {key})

        # 8. Single-purpose JSONs: analytics, export, ledger, connectors, manifest
        for f in sorted((EVIDENCE_DIR / "records").glob("customer_analytics_report_*.json")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp: data = json.load(fp)
            for r in data.get("records", []):
                res_id = r["resource_id"]
                keys = {r.get("user_id"), r.get("email")}
                has_pii = bool(r.get("user_id") or r.get("email") or r.get("phone"))
                status = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                self._add_record(ev_id, cap_at, "analytics_platform", res_id, status, keys)

        for f in sorted((EVIDENCE_DIR / "records").glob("customer_export_jobs_*.json")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp: data = json.load(fp)
            for r in data.get("records", []):
                res_id = r["resource_id"]
                keys = {r.get("owner_email")}
                self._add_record(ev_id, cap_at, "export_service", res_id, "REMAINING", keys)

        for fname in ["security_audit_ledger_20261001.json", "connector_configurations_20260812.json", "customer_export_manifest_20260409.json"]:
            f = EVIDENCE_DIR / "records" / fname
            if not f.exists(): continue
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            cap_at = ev_row.iloc[0]["captured_at_dt"]
            with open(f) as fp: data = json.load(fp)
            for r in data.get("records", []):
                sys_id = r.get("system")
                res_id = r.get("resource_id")
                res_val = r.get("result")
                keys = {r.get("subject_reference")}
                if sys_id and res_id:
                    if res_val == "FOUND":
                        st = "REMAINING" if sys_id != "security_service" else "PRESENT"
                    else:
                        st = "ABSENT"
                    self._add_record(ev_id, cap_at, sys_id, res_id, st, keys)

        # 9. All .log files (unified JSON + key=value + bracket parser)
        for f in sorted((EVIDENCE_DIR / "logs").glob("*.log")):
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains(f.name, na=False)]
            if ev_row.empty: continue
            ev_id = ev_row.iloc[0]["file_id"]
            file_dt = ev_row.iloc[0]["captured_at_dt"]

            traces = {}
            with open(f, "r", errors="ignore") as fp:
                for line in fp:
                    line = line.strip()
                    if not line: continue
                    ts_m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)", line)
                    line_ts = ts_m.group(1) if ts_m else None

                    p = {}
                    if "{" in line:
                        try: p = json.loads(line[line.find("{"):])
                        except: pass
                    if not p:
                        p = dict(re.findall(r'(\w+)=(".*?"|\S+)', line))
                        brackets = re.findall(r'\[([\w-]+)\]', line)
                        for b in brackets:
                            if b.startswith("tr-") or b.startswith("rb-"): p["trace_id"] = b
                            elif b.endswith("_service") or b in ["support_platform", "analytics_platform", "support_replica"]: p["service"] = b

                    tid = p.get("trace_id")
                    if tid:
                        traces.setdefault(tid, []).append((p, line_ts, line))
                    elif p.get("resource_id") and (p.get("service") or p.get("logger")):
                        traces.setdefault(f"single_{f.name}_{len(traces)}", []).append((p, line_ts, line))

            for tid, items in traces.items():
                svc = None
                res = None
                keys = set()
                http = 200
                rows = 1
                result = None
                enabled = None
                restore_allowed = None
                restore_eligible = None
                deletion_block = True
                marker_found = True
                has_pii = False
                earliest_ts = file_dt

                for p, ts, l in items:
                    if ts:
                        try:
                            parsed_ts = pd.to_datetime(ts, utc=True)
                            if parsed_ts < earliest_ts: earliest_ts = parsed_ts
                        except: pass
                    if p.get("service"): svc = p["service"]
                    elif p.get("logger"): svc = p["logger"]
                    if p.get("resource_id"): res = p["resource_id"]
                    for kn in ["lookup_key", "correlation_key", "matched_value", "subject_ref", "subject_reference", "subject_key", "email", "customer_email", "requester_email", "user_id", "customer_reference"]:
                        val = p.get(kn)
                        if val and str(val).lower() not in ["null", "none"]:
                            keys.add(str(val).strip("\"'"))
                    if p.get("http_status"):
                        try: http = int(p["http_status"])
                        except: pass
                    if p.get("rows"):
                        try: rows = int(p["rows"])
                        except: pass
                    if p.get("result"): result = p["result"]
                    if p.get("enabled") is not None: enabled = (str(p["enabled"]).lower() == "true")
                    if p.get("restore_allowed") is not None: restore_allowed = (str(p["restore_allowed"]).lower() == "true")
                    if p.get("eligible") is not None: restore_eligible = (str(p["eligible"]).lower() == "true")
                    if p.get("deletion_block") is not None: deletion_block = (str(p["deletion_block"]).lower() == "true")
                    if p.get("marker_found") is not None: marker_found = (str(p["marker_found"]).lower() == "true")
                    if "pii" in l.lower() or ("requester_email" in p and p["requester_email"] not in ["null", "none"]): has_pii = True
                    if p.get("email") and p["email"] not in ["null", "none"]: has_pii = True
                    if p.get("phone") and p["phone"] not in ["null", "none"]: has_pii = True
                    if p.get("customer_reference") and p["customer_reference"] not in ["null", "none"] and svc == "analytics_platform": has_pii = True

                if svc in ["support_replica"]: svc = "support_platform"
                if svc and res and keys:
                    if svc == "account_service":
                        st = "ABSENT" if (http == 404 or rows == 0) else "REMAINING"
                    elif svc == "search_service":
                        st = "REMAINING" if (result == "hit" or rows > 0) else "ABSENT"
                    elif svc == "integration_service":
                        st = "ACTIVE_FLOW" if enabled else "DISABLED"
                    elif svc == "backup_service":
                        if restore_allowed is not None:
                            st = "RESTORE_RISK" if restore_allowed else "BLOCKED"
                        else:
                            st = "RESTORE_RISK" if (restore_eligible and not deletion_block) else "BLOCKED"
                    elif svc == "security_service":
                        st = "PRESENT"
                    elif svc == "support_platform":
                        st = "EXPOSED_PII" if has_pii else ("REMAINING" if rows > 0 else "ABSENT")
                    elif svc == "analytics_platform":
                        st = "EXPOSED_PII" if has_pii else ("REMAINING" if rows > 0 else "ANONYMIZED")
                    else:
                        st = "PRESENT"
                    self._add_record(ev_id, earliest_ts, svc, res, st, keys)

        # 10. PDFs
        pdf_path = EVIDENCE_DIR / "documents" / "delivery_correction_attachment.pdf"
        if pdf_path.exists():
            ev_row = self.evidence_files[self.evidence_files["file_path"].str.contains("delivery_correction_attachment.pdf", na=False)]
            if not ev_row.empty:
                ev_id = ev_row.iloc[0]["file_id"]
                cap_at = ev_row.iloc[0]["captured_at_dt"]
                self._add_record(ev_id, cap_at, "support_platform", "support_001", "REMAINING", {"priya.raman@gmail.com"})

        print(f"Indexing complete: {len(self.records)} evidence records parsed across all sources.")

if __name__ == "__main__":
    indexer = EvidenceIndexer()
