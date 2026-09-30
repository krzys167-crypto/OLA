#!/usr/bin/env python3
import concurrent.futures
import json
import os
import time
import urllib.request

URL = os.environ.get("OLA_HEALTH_URL", "http://127.0.0.1:8000/health")
REQUESTS = int(os.environ.get("STRESS_REQUESTS", "120"))
CONCURRENCY = int(os.environ.get("STRESS_CONCURRENCY", "12"))
TIMEOUT = float(os.environ.get("STRESS_TIMEOUT", "5"))
P95_LIMIT_MS = float(os.environ.get("STRESS_P95_LIMIT_MS", "500"))
P99_LIMIT_MS = float(os.environ.get("STRESS_P99_LIMIT_MS", "1000"))


def one(_):
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(URL, timeout=TIMEOUT) as r:
            body = r.read()
            ok = r.status == 200 and bool(body)
            err = None if ok else f"status={r.status}"
    except Exception as exc:
        ok = False
        err = repr(exc)
    return (time.perf_counter() - start) * 1000.0, ok, err


def percentile(values, p):
    if not values:
        return float("inf")
    idx = min(len(values) - 1, max(0, int((p / 100.0) * len(values) + 0.999999) - 1))
    return values[idx]

samples = []
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
    for item in pool.map(one, range(REQUESTS)):
        samples.append(item)

latencies = sorted(x[0] for x in samples)
errors = [x[2] for x in samples if not x[1]]
p95 = percentile(latencies, 95)
p99 = percentile(latencies, 99)
error_rate = len(errors) / REQUESTS
result = {
    "benchmark": "OLA-Runtime-Stress-v1",
    "requests": REQUESTS,
    "concurrency": CONCURRENCY,
    "availability": 1.0 - error_rate,
    "error_rate": error_rate,
    "latency_ms_p95": p95,
    "latency_ms_p99": p99,
    "slo": {"availability_min": 0.99, "p95_max_ms": P95_LIMIT_MS, "p99_max_ms": P99_LIMIT_MS},
    "status": "PASS" if not errors and error_rate <= 0.01 and p95 <= P95_LIMIT_MS and p99 <= P99_LIMIT_MS else "FAIL",
    "sample_errors": errors[:5],
}
print(json.dumps(result, sort_keys=True))
with open("stress-evidence.json", "w", encoding="utf-8") as f:
    json.dump(result, f, sort_keys=True, indent=2)
if result["status"] != "PASS":
    raise SystemExit(1)
