#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE_URL = "https://api.openai.com/v1/organization"


def fetch_json(endpoint, params, admin_key):
    rows = []
    page = None
    while True:
        query = list(params.items())
        if page:
            query.append(("page", page))
        query_string = urlencode(query, doseq=True)
        request = Request(
            f"{BASE_URL}/{endpoint}?{query_string}",
            headers={"Authorization": f"Bearer {admin_key}", "Content-Type": "application/json"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (HTTPError, URLError) as exc:
            raise RuntimeError(f"OpenAI {endpoint} export failed: {exc}") from exc
        rows.extend(payload.get("data", []))
        if not payload.get("has_more"):
            return rows
        page = payload.get("next_page")
        if not page:
            raise RuntimeError(f"OpenAI {endpoint} reported has_more without next_page")
        time.sleep(0.1)


def flatten_usage(buckets):
    output = []
    for bucket in buckets:
        start_time = bucket.get("start_time")
        end_time = bucket.get("end_time")
        for result in bucket.get("results", []):
            row = dict(result)
            row["bucket_start_time"] = start_time
            row["bucket_end_time"] = end_time
            output.append(row)
    return output


def flatten_costs(buckets):
    output = []
    for bucket in buckets:
        start_time = bucket.get("start_time")
        end_time = bucket.get("end_time")
        for result in bucket.get("results", []):
            amount = result.get("amount") or {}
            row = dict(result)
            row["bucket_start_time"] = start_time
            row["bucket_end_time"] = end_time
            row["amount_value"] = amount.get("value")
            row["amount_currency"] = amount.get("currency")
            output.append(row)
    return output


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Export real OpenAI organization usage and costs")
    parser.add_argument("--start-time", type=int, required=True, help="Unix seconds, inclusive")
    parser.add_argument("--end-time", type=int, required=True, help="Unix seconds, exclusive")
    parser.add_argument("--out", default="openai-usage-cost-export", help="Output directory")
    args = parser.parse_args()
    if args.end_time <= args.start_time:
        raise SystemExit("--end-time must be greater than --start-time")
    admin_key = os.getenv("OPENAI_ADMIN_KEY")
    if not admin_key:
        raise SystemExit("OPENAI_ADMIN_KEY is required; it is never written to the export")

    usage = fetch_json(
        "usage/completions",
        [
            ("start_time", args.start_time),
            ("end_time", args.end_time),
            ("bucket_width", "1h"),
            ("limit", 168),
            ("group_by[]", "project_id"),
            ("group_by[]", "model"),
            ("group_by[]", "api_key_id"),
        ],
        admin_key,
    )
    costs = fetch_json(
        "costs",
        [
            ("start_time", args.start_time),
            ("end_time", args.end_time),
            ("bucket_width", "1d"),
            ("limit", 180),
            ("group_by[]", "project_id"),
            ("group_by[]", "line_item"),
        ],
        admin_key,
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    usage_raw = out / "usage-completions.json"
    costs_raw = out / "costs.json"
    usage_csv = out / "usage-completions.csv"
    costs_csv = out / "costs.csv"
    manifest = out / "EXPORT-MANIFEST.json"

    usage_raw.write_text(json.dumps(usage, sort_keys=True, indent=2), encoding="utf-8")
    costs_raw.write_text(json.dumps(costs, sort_keys=True, indent=2), encoding="utf-8")
    write_csv(usage_csv, flatten_usage(usage))
    write_csv(costs_csv, flatten_costs(costs))

    manifest_data = {
        "schema": "ola-openai-usage-cost-export/v1",
        "source": "OpenAI Organization Usage API + Costs API",
        "start_time": args.start_time,
        "end_time": args.end_time,
        "usage_rows": len(flatten_usage(usage)),
        "cost_rows": len(flatten_costs(costs)),
        "usage_endpoint": "/v1/organization/usage/completions",
        "cost_endpoint": "/v1/organization/costs",
        "financial_source_of_truth": "costs_endpoint",
        "files": {},
    }
    for path in [usage_raw, costs_raw, usage_csv, costs_csv]:
        manifest_data["files"][path.name] = sha256_file(path)
    manifest.write_text(json.dumps(manifest_data, sort_keys=True, indent=2), encoding="utf-8")
    (out / "SHA256SUMS.txt").write_text(
        "".join(f"{sha256_file(p)}  {p.name}\n" for p in [usage_raw, costs_raw, usage_csv, costs_csv, manifest]),
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "EXPORTED",
        "out": str(out),
        "usage_rows": manifest_data["usage_rows"],
        "cost_rows": manifest_data["cost_rows"],
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"EXPORT_BLOCKED={exc}", file=sys.stderr)
        raise
