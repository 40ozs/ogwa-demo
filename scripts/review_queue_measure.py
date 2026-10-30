"""Time GET /review-queue on synthetic tenants larger than the demo (OGWA-REVIEW-QUEUE-API-01).

    python scripts/review_queue_measure.py [--groups 4400 13200] [--repeat 5]

Builds tests/scale_fixtures.ScaleTenant (one candidate per four groups; a third of them diverted to
blocked and closed states, as tests/test_review_queue_api.py does), then requests the queue in-process
(CPython, no network) per page size and filter: the first request (cold: fresh process caches) and
the median of ``--repeat`` warm ones, as wall and CPU milliseconds. Synthetic data only. Prints JSON.
This measures the application code; the hosted Worker (Pyodide) is measured with ``wrangler tail``.
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.validation import encode_cursor  # noqa: E402
from tests.api_fixtures import AUTOMATION, SECURITY  # noqa: E402
from tests.scale_fixtures import ScaleTenant  # noqa: E402

CASES = [("open", 25, None), ("all", 50, None), ("blocked", 25, None), ("closed", 50, None),
         ("all", 25, "deadline"), ("all", 50, "middle"), ("all", 50, "last")]


def timed(client, path: str) -> tuple[float, float, dict]:
    wall, cpu = time.perf_counter(), time.process_time()
    result = client.get(path)
    assert result.status == 200, result.json
    return (time.perf_counter() - wall) * 1000, (time.process_time() - cpu) * 1000, result.json


def measure(groups: int, repeat: int) -> dict:
    tenant = ScaleTenant(groups=groups)
    try:
        automation = tenant.client(AUTOMATION)
        ids = [r["id"] for r in tenant.store.connection.execute("SELECT id FROM candidates ORDER BY id")]
        targets = ("BLOCKED", "EXCLUDED", "MAPPING_AMBIGUOUS", "REJECTED", "PROTECTED")
        for i, cid in enumerate(ids[::3]):
            assert automation.post(f"/api/v1/candidates/{cid}/transitions",
                                   {"target": targets[i % len(targets)], "reason": "measurement fixture"}).status == 201
        client = tenant.client(SECURITY)
        rows = []
        for status, limit, extra in CASES:
            path = f"/api/v1/review-queue?status={status}&limit={limit}"
            if extra == "deadline":
                path += "&sort=deadline&order=asc"
            elif extra in ("middle", "last"):
                total = client.get(path).json["page"]["total"]
                offset = (total // 2) if extra == "middle" else (total - 1) // limit * limit
                path += f"&cursor={encode_cursor(offset)}"
            cold_wall, cold_cpu, body = timed(client, path)
            warm = [timed(client, path)[:2] for _ in range(repeat)]
            rows.append({"status": status, "limit": limit, "variant": extra or "first page",
                         "rows": len(body["items"]), "filteredTotal": body["page"]["total"],
                         "coldWallMs": round(cold_wall, 1), "coldCpuMs": round(cold_cpu, 1),
                         "warmWallMsMedian": round(statistics.median(w for w, _ in warm), 1),
                         "warmCpuMsMedian": round(statistics.median(c for _, c in warm), 1)})
        return {"candidates": len(ids), "groups": groups, "cases": rows}
    finally:
        tenant.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--groups", type=int, nargs="+", default=[4400])
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps({"python": sys.version.split()[0], "tenants": [measure(g, args.repeat) for g in args.groups]},
                     indent=2))


if __name__ == "__main__":
    main()
