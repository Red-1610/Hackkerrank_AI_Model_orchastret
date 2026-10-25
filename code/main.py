import sys
import os
from pathlib import Path
import json
import argparse
import pandas as pd


CODE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CODE_DIR.parent if CODE_DIR.name == "code" else CODE_DIR
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from pipeline import AuditEngine, step_sort_key

def run(sample: bool = False, output_path: Optional[str] = None):
    dataset_dir = REPO_ROOT / "dataset"
    if sample:
        req_file = dataset_dir / "sample_deletion_requests.csv"
        default_out = REPO_ROOT / "sample_output_generated.csv"
    else:
        req_file = dataset_dir / "deletion_requests.csv"
        default_out = REPO_ROOT / "output.csv"

    out_file = Path(output_path) if output_path else default_out

    print(f"Initializing Deletion Audit Engine from: {dataset_dir}")
    engine = AuditEngine(dataset_dir)

    print(f"Reading requests from: {req_file}")
    df_req = pd.read_csv(req_file)

    results = []
    total = len(df_req)
    print(f"Auditing {total} cases...")

    for idx, row in df_req.iterrows():
        res = engine.audit_case(
            case_id=row["case_id"],
            email=row["email"],
            requested_at_str=row["requested_at"],
            reported_status=row["reported_status"],
            reported_at_str=row["reported_at"],
            audit_at_str=row["audit_at"],
            request_text=row["request_text"]
        )
        results.append(res)

    out_df = pd.DataFrame(results)
    out_df["_sort_num"] = out_df["case_id"].apply(lambda x: int(x.split("_")[1]) if "_" in x else 0)
    out_df = out_df.sort_values("_sort_num").reset_index(drop=True)
    out_df = out_df[["case_id", "deletion_status", "steps_json"]]

    out_df.to_csv(out_file, index=False)
    print(f"Successfully generated {len(out_df)} rows -> {out_file}")

if __name__ == "__main__":
    from typing import Optional
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Pipeline")
    parser.add_argument("--sample", action="store_true", help="Run on sample_deletion_requests.csv instead of full dataset")
    parser.add_argument("--output", type=str, default=None, help="Custom output CSV path")
    args = parser.parse_args()

    run(sample=args.sample, output_path=args.output)
