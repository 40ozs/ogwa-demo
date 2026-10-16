"""Docker acceptance check for the demo (README, "Quick start with Docker").

    python scripts/docker_smoke.py

Every Compose call runs in the smoke's own project (``-p ogwa-docker-smoke``), with its own
demo store volume, so it never touches your ``docker compose`` project or its demo store.

1. ``docker compose up -d --build --wait``: the image builds and the service becomes healthy.
2. The smoke checks (``scripts/hosted_smoke.py --local``) against http://localhost:8765.
3. The fresh demo store verifies against the pinned audit head; after the smoke checks (which
   chain their refused requests into the audit log) the chain still verifies.
4. Live or production configuration refuses to start; generic variables such as
   ``ENV=production`` change nothing (health still reports ``liveIntegrations: false``).
5. With no network at all (``--network none``) the image seeds, verifies, and serves.
6. The documented reset (``docker compose down -v``, then ``up``) seeds the same store again.

Ends with ``docker compose -p ogwa-docker-smoke down -v``, which deletes only the smoke's own
volume. It rebuilds the shared ``ogwa-demo:local`` image from this checkout. Needs Docker with
Compose v2, port 8765 free (stop your own demo first: ``docker compose stop``), and Python 3.11+
on the host for the smoke checks. Exits 1 if any check fails.
"""

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://localhost:8765"
IMAGE = "ogwa-demo:local"
AUDIT_HEAD = "sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41"
PROBE = "ogwa-demo-env-probe"
PROJECT = "ogwa-docker-smoke"  # never the default project: `down -v` deletes the project's demo store
REFUSED = ({"OGWA_RUNTIME_MODE": "production"}, {"OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION"},
           {"OGWA_EXECUTION_MODE": "PRODUCTION_MUTATION"}, {"OGWA_OKTA_ORG_URL": "https://synthetic.okta.example"},
           {"OGWA_OKTA_API_TOKEN": "synthetic-token"}, {"OGWA_AAP_URL": "https://aap.synthetic.example"},
           {"OGWA_LIVE_INTEGRATIONS": "true"}, {"OGWA_PRODUCTION": "true"}, {"OGWA_DEMO_MODE": "false"},
           {"OKTA_API_TOKEN": "synthetic-token"})
IGNORED = {"PRODUCTION": "true", "LIVE_INTEGRATIONS": "true", "DEMO_MODE": "false", "ENV": "production",
           "MODE": "production"}
HEALTH = ("import json, time, urllib.request as u\n"
          "for _ in range(60):\n"
          "    try:\n"
          "        print(json.dumps(json.load(u.urlopen('http://127.0.0.1:8765/api/v1/health', timeout=2)))); break\n"
          "    except OSError:\n"
          "        time.sleep(1)\n")
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}".rstrip(), flush=True)


def run(*args, check_=False):
    return subprocess.run(list(args), cwd=ROOT, text=True, capture_output=True, check=check_)


def compose(*args, check_=False):
    return run("docker", "compose", "-p", PROJECT, *args, check_=check_)


def health():
    with urllib.request.urlopen(f"{ORIGIN}/api/v1/health", timeout=5) as response:
        return json.load(response)


def verify_head(label, pinned=True):
    r = compose("exec", "-T", "ogwa", "python", "-m", "app.runtime", "verify",
                *(("--expected-audit-head", AUDIT_HEAD) if pinned else ()))
    check(f"{label}: demo store verifies" + (" against the pinned audit head" if pinned else " (audit chain intact)"),
          r.returncode == 0 and (AUDIT_HEAD in r.stdout or not pinned), (r.stdout + r.stderr).strip().splitlines()[-1:])


def main() -> int:
    compose("down", "-v")
    up = compose("up", "-d", "--build", "--wait")
    check("image builds and the service becomes healthy", up.returncode == 0, up.stderr.strip().splitlines()[-1:])
    if up.returncode:
        print(compose("logs").stdout[-3000:])
        return 1
    body = health()
    check("health: demo runtime, Null Meridian, liveIntegrations false",
          (body.get("status"), body.get("runtimeMode"), body.get("organization"), body.get("liveIntegrations"))
          == ("ok", "demo", "Null Meridian", False))
    verify_head("fresh store")
    smoke = run(sys.executable, "scripts/hosted_smoke.py", ORIGIN, "--local")
    print(smoke.stdout + smoke.stderr)
    check("smoke checks (hosted_smoke.py --local)", smoke.returncode == 0, smoke.stdout.strip().splitlines()[-1:])
    verify_head("after the smoke checks (refusals recorded)", pinned=False)
    user = compose("exec", "-T", "ogwa", "id", "-u").stdout.strip()
    check("the server runs as a non-root user", user not in ("", "0"), f"uid {user}")

    for env in REFUSED:
        flags = [x for key, value in env.items() for x in ("-e", f"{key}={value}")]
        r = compose("run", "--rm", "--no-deps", *flags, "ogwa")
        check(f"refused: {' '.join(env)}", r.returncode == 2 and "Demo Mode only" in r.stderr + r.stdout,
              f"exit {r.returncode}")
    compose("stop", "ogwa")
    run("docker", "rm", "-f", PROBE)
    flags = [x for key, value in IGNORED.items() for x in ("-e", f"{key}={value}")]
    probe = compose("run", "-d", "--name", PROBE, "--service-ports", "--no-deps", *flags, "ogwa")
    body = {}
    for _ in range(60):
        try:
            body = health()
            break
        except OSError:
            time.sleep(1)
    check(f"ignored: {' '.join(IGNORED)} (still the demo, liveIntegrations false)",
          probe.returncode == 0 and (body.get("runtimeMode"), body.get("liveIntegrations")) == ("demo", False))
    run("docker", "rm", "-f", PROBE)

    offline = run("docker", "run", "--rm", "--network", "none", IMAGE, "sh", "-c",
                  "python -m app.runtime reset-demo --confirm-synthetic-reset > /dev/null"
                  f" && python -m app.runtime verify --expected-audit-head {AUDIT_HEAD} > /dev/null"
                  f" && {{ python -m app.api serve 2> /dev/null & }} && python -c \"{HEALTH}\"")
    try:
        body = json.loads(offline.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        body = {}
    check("--network none: seeds, verifies the pinned head, serves; liveIntegrations false",
          offline.returncode == 0 and (body.get("status"), body.get("liveIntegrations")) == ("ok", False),
          offline.stderr.strip().splitlines()[-1:])

    compose("down", "-v")
    up = compose("up", "-d", "--wait")
    check("reset: down -v, then up, seeds a fresh store", up.returncode == 0)
    verify_head("after the reset")
    compose("down", "-v")
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} Docker checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
