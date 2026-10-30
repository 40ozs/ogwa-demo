"""Browser-test harness: a synthetic OGWA server on loopback and a disposable headless browser.

Safety:
- The server is a fresh, in-memory synthetic world (``tests.api_fixtures.World``), built in
  its own thread. ``var/`` and its anchored store are never opened.
- ``DemoServer`` instead starts the demo runtime exactly as an operator does
  (``OGWA_RUNTIME_MODE=demo python -m app.api serve``), over a demo store reset by the demo
  reset into a temporary directory that is deleted afterwards. It also binds loopback only.
- The browser runs headless with a throw-away profile in a temporary directory, which is
  deleted afterwards. ``--host-resolver-rules`` maps every host name except 127.0.0.1 to
  "not found", so neither the page nor the browser itself can reach any other system by
  name; background networking, sync, extensions, and component updates are switched off.
- The DevTools port is chosen by the browser on loopback and read from its profile.
- Screenshots are written only when ``UI_BROWSER_SCREENSHOTS`` names a directory; they show
  synthetic data only and are not test artefacts to commit.
- ``HostedDemoServer`` serves the Cloudflare Worker's own application
  (``app.cloudflare.hosted.HostedDemo``) the way the Worker runs it, on loopback.
- ``UI_BROWSER_TARGET`` (an origin, such as the local Worker on http://127.0.0.1:8787 or the
  deployed one on workers.dev) points the demo modules at a public demo that is already
  serving, instead of a local server. The target's dataset, scenario candidate ids, and
  walkthrough parts are read from its own API (``target_demo``), never assumed from a local
  seed. A module that asserts no dataset-specific content (``any_dataset=True``) runs against
  any demo dataset; any other module skips unless the target serves its dataset
  (docs/deployment/hosted-demo-fixtures.md). The browser can then resolve that one host too,
  and still nothing else.
"""

import base64
import functools
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from datetime import timedelta
import time
import unittest
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from app.api.local import build_local_api, make_local_server
from app.ui.server import OgwaWebApp
from tests.api_fixtures import World
from tests.browser.cdp import Cdp, CdpError

ENABLE_VAR = "UI_BROWSER_TESTS"
BROWSER_VAR = "UI_BROWSER"
SCREENSHOT_VAR = "UI_BROWSER_SCREENSHOTS"
TARGET_VAR = "UI_BROWSER_TARGET"
CANDIDATE_BROWSERS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)
BROWSER_FLAGS = (
    "--headless=new",
    "--remote-debugging-port=0",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-extensions",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication,CertificateTransparencyComponentUpdater",
    "--metrics-recording-only",
    "--no-pings",
    "--password-store=basic",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--window-size=1280,900",
)


def enabled() -> bool:
    return os.environ.get(ENABLE_VAR) == "1"


def target() -> str | None:
    """The origin of an already-serving public demo (the Worker) to test instead of a local server."""
    raw = os.environ.get(TARGET_VAR)
    if not raw:
        return None
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") or parts.query \
            or parts.fragment or parts.username or parts.password:
        raise ValueError(f"{TARGET_VAR} must be an origin such as https://host.example")
    return f"{parts.scheme}://{parts.netloc}"


def walkthrough_parts(dataset_key: str) -> dict[str, str]:
    """The dataset's walkthrough parts ("data-quality", "controlled-remediation") → their scenario keys; {} if none."""
    from app.demo.datasets import dataset

    guide = dataset(dataset_key).walkthrough()
    return {p["key"]: p["candidateKey"] for p in guide["parts"]} if guide else {}


@functools.cache
def target_demo() -> dict:
    """What the target serves, read from its own API as its anonymous visitor (GETs only): the dataset key from
    ``GET /health``, and from ``GET /demo-scenarios`` each scenario's candidate id by key and each walkthrough part's
    scenario key. https needs a CA bundle Python can read (on macOS python.org builds: SSL_CERT_FILE=/etc/ssl/cert.pem)."""
    def get(path: str, cookie: str = "") -> tuple[list[str], dict]:
        # Cloudflare refuses Python-urllib's default user agent (error 1010), as scripts/hosted_smoke.py notes.
        headers = {"User-Agent": "ogwa-browser-gate/1.0", **({"Cookie": cookie} if cookie else {})}
        with urllib.request.urlopen(urllib.request.Request(f"{target()}/api/v1{path}", headers=headers),
                                    timeout=60) as response:
            return response.headers.get_all("Set-Cookie") or [], json.load(response)

    _, health = get("/health")
    if not (health.get("publicDemo") and (health.get("dataset") or {}).get("key")):
        raise CdpError(f"{TARGET_VAR} is not a public demo: GET /health answered {health}")
    cookies, _ = get("/session")
    cookie = next(c.split(";", 1)[0] for c in cookies if c.startswith("__Host-ogwa-session="))
    _, data = get("/demo-scenarios", cookie)
    return {"dataset": health["dataset"]["key"],
            "scenarios": {s["candidateKey"]: s["candidateId"] for s in data["items"] if s.get("candidateKey")},
            "walkthrough": {p["key"]: p["candidateKey"] for p in (data.get("walkthrough") or {}).get("parts", [])}}


def adopt_target(server, any_dataset: bool) -> None:
    """Point ``server`` at the target, or skip the module when it asserts another dataset's content."""
    demo = target_demo()
    if demo["dataset"] != server.dataset and not any_dataset:
        raise unittest.SkipTest(f"{TARGET_VAR} serves {demo['dataset']}; this module asserts {server.dataset} content "
                                "(docs/deployment/hosted-demo-fixtures.md)")
    server.origin, server.dataset = target(), demo["dataset"]
    server.scenarios, server.walkthrough = demo["scenarios"], demo["walkthrough"]


def browser_flags() -> tuple[str, ...]:
    """``BROWSER_FLAGS``, letting the browser also resolve the target's host (and nothing else)."""
    host = urlsplit(target()).hostname if target() else None
    if host in (None, "127.0.0.1"):
        return BROWSER_FLAGS
    lockdown = "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
    return tuple(f"{flag} , EXCLUDE {host}" if flag == lockdown else flag for flag in BROWSER_FLAGS)


def browser_path() -> str | None:
    chosen = os.environ.get(BROWSER_VAR)
    if chosen:
        return chosen if Path(chosen).is_file() else None
    return next((p for p in CANDIDATE_BROWSERS if Path(p).is_file()), None)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SyntheticServer(threading.Thread):
    """A seeded synthetic world served as UI + API on 127.0.0.1, entirely inside this thread."""

    def __init__(self, refresh: tuple[str, ...] = ("S07", "S14"), dataset: str = "classic",
                 any_dataset: bool = False, advance: timedelta | None = None) -> None:
        super().__init__(daemon=True)
        self.dataset = dataset
        self.advance = advance  # moves the world's clock on after seeding, before any refresh
        self.any_dataset = any_dataset  # the module asserts no dataset-specific content: any target's demo will do
        self.walkthrough = walkthrough_parts(dataset)
        self.port = free_port()
        self.origin = f"http://127.0.0.1:{self.port}"
        self.refresh = refresh
        self.ready = threading.Event()
        self.scenarios: dict[str, str] = {}
        self.error: BaseException | None = None
        self.httpd = None

    def run(self) -> None:
        world = None
        try:
            world = World(dataset=self.dataset)
            if self.advance:
                world.clock.advance(self.advance)
            for key in self.refresh:  # fresh enough for execution-grade checks (24 h), facts unchanged
                world.refresh_evidence(world.candidate(key))
            self.scenarios = {s.key: s.candidate_id for s in world.summary.scenarios}
            api = build_local_api(world.store, clock=world.clock, port=self.port, logger=world.api.log)
            self.httpd = make_local_server(OgwaWebApp(api), self.port)
        except BaseException as exc:  # surfaced by start_and_wait
            self.error = exc
            self.ready.set()
            if world:
                world.close()
            return
        self.ready.set()
        try:
            self.httpd.serve_forever(poll_interval=0.1)
        finally:
            self.httpd.server_close()
            world.close()

    def start_and_wait(self) -> "SyntheticServer":
        if target():
            adopt_target(self, self.any_dataset)
            return self
        self.start()
        self.ready.wait(60)
        if self.error:
            raise self.error
        return self

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
        if self.is_alive():  # never started when a target serves instead
            self.join(10)


class DemoServer:
    """The demo runtime as an operator starts it, over a freshly reset demo store.

    The demo store is reset in this process with the demo reset (``app.runtime.demo_store``)
    into a temporary ``var/``; the server is then ``python -m app.api serve`` in a child
    process whose environment selects ``OGWA_RUNTIME_MODE=demo`` and holds no other OGWA
    setting. ``dataset`` is a registry selector; None means the legacy Null Meridian dataset, which these
    browser suites were written against (the runtime's default is Genesee Press since SYNTH-OGWA-01)."""

    REPO_ROOT = Path(__file__).resolve().parents[2]

    def __init__(self, dataset: str | None = None, any_dataset: bool = False) -> None:
        self.dataset = dataset or "null-meridian"
        self.any_dataset = any_dataset
        self.walkthrough = walkthrough_parts(self.dataset)
        self.port = free_port()
        self.origin = f"http://127.0.0.1:{self.port}"
        self.tmp = Path(tempfile.mkdtemp(prefix="ogwa-ui-demo-"))
        self.scenarios: dict[str, str] = {}
        self.process: subprocess.Popen | None = None
        self.log = self.tmp / "server.log"

    def start_and_wait(self) -> "DemoServer":
        if target():
            adopt_target(self, self.any_dataset)
            return self
        env = self._reset()
        base = {k: v for k, v in os.environ.items() if not k.upper().startswith("OGWA_")}
        with self.log.open("wb") as log:
            self.process = subprocess.Popen([sys.executable, "-m", "app.api", "serve", "--port", str(self.port)],
                                            cwd=self.REPO_ROOT, env={**base, **env}, stdout=log, stderr=log)
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(f"{self.origin}/api/v1/health", timeout=2) as response:
                    if response.status == 200:
                        return self
            except OSError:
                pass
            if self.process.poll() is not None or time.monotonic() > deadline:
                output = self.log.read_text(encoding="utf-8", errors="replace")
                self.stop()
                raise CdpError(f"the demo server did not start:\n{output}")
            time.sleep(0.1)

    def _reset(self) -> dict[str, str]:
        """The demo reset into this server's throw-away ``var/``; returns the demo environment."""
        from app.core.config import load_settings
        from app.runtime.datasets import resolve_dataset
        from app.runtime.demo_store import reset_demo_store

        root = self.tmp / "var"
        root.mkdir()
        env = {"OGWA_RUNTIME_MODE": "demo", "OGWA_DATABASE_URL": f"sqlite:///{(root / 'ogwa-demo.sqlite3').as_posix()}"}
        if self.dataset:
            env["OGWA_DEMO_DATASET"] = self.dataset
        settings = load_settings(env)
        reset = reset_demo_store(settings, resolve_dataset(settings.demo_dataset), confirmed=True, allowed_root=root)
        self.scenarios = {s.key: s.candidate_id for s in reset.summary.scenarios}
        self.image = (root / "ogwa-demo.sqlite3").read_bytes()
        return env

    def stop(self) -> None:
        try:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(10)
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)


class HostedDemoServer(DemoServer):
    """The Cloudflare Worker's application (``HostedDemo``) on loopback, driven through
    ``HostedDemo.handle`` exactly as the Worker drives it, over the bytes of a demo store reset by
    the demo reset. The UI files are served as Workers Static Assets serve them (with the local
    server's headers). D1 is stood in for by the store itself: it holds the same store, as the
    Worker requires. With ``UI_BROWSER_TARGET``, the deployed (or ``wrangler dev``) Worker instead, whatever
    dataset it serves. Locally, the dataset the Worker is configured with (Genesee Press)."""

    def __init__(self, dataset: str | None = "genesee-press") -> None:
        super().__init__(dataset, any_dataset=True)

    def start_and_wait(self) -> "HostedDemoServer":
        if target():
            return super().start_and_wait()
        from app.cloudflare.hosted import HostedDemo
        from app.cloudflare.identity import SCHEMA_SQL
        from app.ui.server import UI_HEADERS, StaticAssets

        self._reset()
        hosted = HostedDemo(lambda: self.image, {"OGWA_RUNTIME_MODE": "demo",
                                                 "OGWA_DEMO_DATASET": self.dataset or "null-meridian"})
        connection = hosted.app.store.connection
        assert hosted.check_environment({"OGWA_RUNTIME_MODE": "demo", "OGWA_DEMO_DATASET": self.dataset or "null-meridian",
                                         "HOSTED_SESSION_KEY": secrets.token_hex(32)})
        assert hosted.check_schema([dict(r) for r in connection.execute(SCHEMA_SQL)])
        assets = StaticAssets()

        def app(environ, start_response):
            path = environ.get("PATH_INFO") or "/"
            asset = None if path.startswith("/api/") else assets.get(path)
            if asset is not None and environ["REQUEST_METHOD"] in ("GET", "HEAD"):
                start_response("200 OK", [("Content-Type", asset[0]), *UI_HEADERS, ("X-OGWA-Runtime-Mode", "demo")])
                return [asset[1]]
            if not hosted.check_d1(hosted.identity.to_json()):
                status, headers, body = hosted.unavailable()
            else:
                length = int(environ.get("CONTENT_LENGTH") or 0)
                headers = [(k[5:].replace("_", "-").lower(), v) for k, v in environ.items() if k.startswith("HTTP_")]
                headers += [(k.replace("_", "-").lower(), environ[k]) for k in ("CONTENT_TYPE", "CONTENT_LENGTH")
                            if environ.get(k)]
                url = f"{self.origin}{path}" + (f"?{environ['QUERY_STRING']}" if environ.get("QUERY_STRING") else "")
                status, headers, body = hosted.handle(environ["REQUEST_METHOD"], url, headers,
                                                      environ["wsgi.input"].read(length) if length else b"")
            start_response(f"{status} -", headers)
            return [body]

        self.httpd = make_local_server(app, self.port)
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
        return self

    def stop(self) -> None:
        try:
            if getattr(self, "httpd", None):
                self.httpd.shutdown()
                self.httpd.server_close()
        finally:
            super().stop()


class Browser:
    """A headless browser with one page, driven over DevTools."""

    def __init__(self, executable: str) -> None:
        self.profile = tempfile.mkdtemp(prefix="ogwa-ui-browser-")
        self.process = subprocess.Popen([executable, *browser_flags(), f"--user-data-dir={self.profile}", "about:blank"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port_file = Path(self.profile) / "DevToolsActivePort"
        deadline = time.monotonic() + 30
        while not port_file.is_file() or not port_file.read_text(encoding="utf-8").strip():
            if time.monotonic() > deadline or self.process.poll() is not None:
                self.close()
                raise CdpError("the browser did not open a DevTools port")
            time.sleep(0.1)
        port = int(port_file.read_text(encoding="utf-8").splitlines()[0])
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=10) as response:
            ws_url = json.load(response)["webSocketDebuggerUrl"]
        self.cdp = Cdp(ws_url)
        self._open_page()

    def _open_page(self) -> None:
        self.target = self.cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = self.cdp.send("Target.attachToTarget", {"targetId": self.target, "flatten": True})["sessionId"]
        for domain in ("Page", "Runtime", "Network", "Log"):
            self.send(f"{domain}.enable")

    # --- plumbing ---------------------------------------------------------------------------

    def send(self, method: str, params: dict | None = None) -> dict:
        return self.cdp.send(method, params, session=self.session)

    def evaluate(self, expression: str):
        result = self.send("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in result:
            raise CdpError(f"page script failed: {result['exceptionDetails'].get('text')}")
        return result["result"].get("value")

    def wait_for(self, expression: str, timeout: float = 15.0, message: str = ""):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                last = self.evaluate(f"!!({expression})")  # a DOM node would arrive as {} (falsy in Python)
            except CdpError:
                last = None
            if last:
                return last
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {message or expression!r} (last value {last!r})")

    def goto(self, url: str) -> None:
        self.send("Page.navigate", {"url": url})

    # --- page helpers -----------------------------------------------------------------------

    def title(self) -> str:
        return self.evaluate("document.getElementById('page-title').textContent")

    def wait_title(self, text: str, timeout: float = 15.0) -> None:
        self.wait_for(f"document.getElementById('page-title').textContent === {json.dumps(text)}", timeout,
                      f"page title {text!r}")

    def wait_title_prefix(self, prefix: str, timeout: float = 15.0) -> None:
        self.wait_for(f"document.getElementById('page-title').textContent.startsWith({json.dumps(prefix)})", timeout,
                      f"page title starting {prefix!r}")

    def text(self, selector: str = "main") -> str:
        return self.evaluate(f"(document.querySelector({json.dumps(selector)}) || {{innerText: ''}}).innerText")

    def active(self) -> dict:
        return self.evaluate("""(() => { const el = document.activeElement; return {
            tag: el.tagName.toLowerCase(), id: el.id, text: (el.innerText || el.value || '').trim().slice(0, 200),
            cls: el.className, labels: el.labels ? [...el.labels].map(l => l.textContent) : [] }; })()""")

    def focus(self, selector: str) -> None:
        self.evaluate(f"document.querySelector({json.dumps(selector)}).focus()")

    def focus_button(self, label: str) -> None:
        found = self.evaluate(f"""(() => {{ const b = [...document.querySelectorAll('button')]
            .find(x => x.textContent.trim() === {json.dumps(label)}); if (!b) return false; b.focus(); return true; }})()""")
        if not found:
            raise AssertionError(f"no button labelled {label!r}")

    def buttons(self) -> list[str]:
        return self.evaluate("[...document.querySelectorAll('button')].map(b => b.textContent.trim())")

    def key(self, key: str) -> None:
        codes = {"Tab": 9, "Enter": 13, "Escape": 27, " ": 32, "End": 35, "Home": 36, "ArrowLeft": 37, "ArrowRight": 39}
        base = {"key": key, "code": "Space" if key == " " else key, "windowsVirtualKeyCode": codes[key],
                "nativeVirtualKeyCode": codes[key]}
        down = {**base, "type": "keyDown"}
        if key in ("Enter", " "):
            down["text"] = "\r" if key == "Enter" else " "
        self.send("Input.dispatchKeyEvent", down)
        self.send("Input.dispatchKeyEvent", {**base, "type": "keyUp"})

    def type(self, text: str) -> None:
        self.send("Input.insertText", {"text": text})

    def viewport(self, width: int, height: int, mobile: bool = False) -> None:
        self.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1,
                                                         "mobile": mobile})

    def media(self, features: list[dict]) -> None:
        self.send("Emulation.setEmulatedMedia", {"features": features})

    # --- a slow or failing network, on cue (no sleeps) ------------------------------------------

    def hold(self, url_pattern: str | None, stage: str = "Request") -> None:
        """Pause this page's requests to URLs matching ``url_pattern`` (a DevTools Fetch glob) until each is
        released; ``stage="Response"`` pauses them once the answer has arrived. ``None`` stops pausing."""
        if url_pattern is None:
            self.send("Fetch.disable")
        else:
            self.send("Fetch.enable", {"patterns": [{"urlPattern": url_pattern, "requestStage": stage}]})

    def held(self, timeout: float = 15.0) -> dict:
        """The next request ``hold`` paused (its ``Fetch.requestPaused`` parameters), once the page has made it."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for event in self.cdp.events:
                if event.get("method") == "Fetch.requestPaused" and event.get("sessionId") == self.session:
                    self.cdp.events.remove(event)
                    return event["params"]
            self.evaluate("0")  # a round trip reads the events that arrived meanwhile
        raise CdpError("no request was held")

    def release(self, request: dict, fail: bool = False) -> None:
        """Let a held request go on, or drop its connection, as a network failure would."""
        if fail:
            self.send("Fetch.failRequest", {"requestId": request["requestId"], "errorReason": "ConnectionClosed"})
        else:
            self.send("Fetch.continueRequest", {"requestId": request["requestId"]})

    def screenshot(self, name: str) -> None:
        directory = os.environ.get(SCREENSHOT_VAR)
        if not directory:
            return
        data = self.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})["data"]
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / f"{name}.png").write_bytes(base64.b64decode(data))

    def csp_probe(self, url: str) -> dict:
        """Open ``url`` in a separate, throw-away tab and try what its CSP must forbid: an HTML
        sink (Trusted Types), an image from another origin, and an inline style attribute.
        The violations this causes are that tab's own, so they never mask a problem in the
        main tab, whose events ``problems()`` checks.

        eval is not probed: code run through DevTools is exempt from CSP's eval rule, so a
        probe could not tell. The header itself is pinned by tests/test_ui_server.py."""
        target = self.cdp.send("Target.createTarget", {"url": url})["targetId"]
        session = self.cdp.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        try:
            def run(expression):
                reply = self.cdp.send("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                           "awaitPromise": True}, session=session)
                return reply["result"].get("value")

            deadline = time.monotonic() + 15
            # The new tab starts on about:blank, which is already "complete": wait for the probed page.
            while run(f"document.readyState === 'complete' && location.href === {json.dumps(url)}") is not True:
                if time.monotonic() > deadline:
                    raise CdpError("the probe tab did not load")
                time.sleep(0.05)
            return {
                "innerHTML": run("(() => { try { document.createElement('div').innerHTML = '<b>x</b>'; return 'allowed'; }"
                                 " catch (e) { return e.name; } })()"),
                "violations": run("""new Promise((resolve) => {
                    const seen = [];
                    document.addEventListener('securitypolicyviolation', (e) => seen.push(e.violatedDirective));
                    const img = document.createElement('img');
                    img.src = 'http://blocked.invalid/probe.png';  // .invalid never resolves (RFC 2606)
                    const div = document.createElement('div');
                    div.setAttribute('style', 'color: red');
                    document.body.append(img, div);
                    setTimeout(() => resolve([...new Set(seen)].sort()), 500);
                })"""),
            }
        finally:
            self.cdp.send("Target.closeTarget", {"targetId": target})

    # --- what the page did ------------------------------------------------------------------

    def writes(self) -> list[str]:
        """Every request this browser sent that is not a read (GET, HEAD, OPTIONS), in every tab: "METHOD url"."""
        requests = [e["params"]["request"] for e in self.cdp.events if e.get("method") == "Network.requestWillBeSent"]
        return [f"{r['method']} {r['url']}" for r in requests if r["method"] not in ("GET", "HEAD", "OPTIONS")]

    def requested_urls(self) -> list[str]:
        return [e["params"]["request"]["url"] for e in self.cdp.events if e.get("method") == "Network.requestWillBeSent"]

    def problems(self) -> list[str]:
        """Uncaught exceptions, console errors, browser log errors (CSP violations among them), and 5xx answers.

        The browser also logs every 4xx response as a "network" error. Those are expected here
        (the session probe before sign-in is a 401; refusals are 403/409) and are left out."""
        out = []
        for e in self.cdp.events:
            if e.get("sessionId") != self.session:
                continue  # another tab: only csp_probe opens one, to cause violations on purpose
            method, params = e.get("method"), e.get("params", {})
            if method == "Network.responseReceived" and params["response"]["status"] >= 500:
                out.append(f"server error {params['response']['status']}: {params['response']['url']}")
            elif method == "Log.entryAdded" and params["entry"].get("source") == "network":
                continue
            elif method == "Runtime.exceptionThrown":
                out.append(f"exception: {params['exceptionDetails'].get('text')} "
                           f"{(params['exceptionDetails'].get('exception') or {}).get('description', '')[:300]}")
            elif method == "Runtime.consoleAPICalled" and params.get("type") in ("error", "assert"):
                out.append("console: " + " ".join(str(a.get("value", a.get("description", ""))) for a in params.get("args", [])))
            elif method == "Log.entryAdded" and params["entry"].get("level") == "error":
                out.append(f"log: {params['entry'].get('text')} {params['entry'].get('url', '')}")
        return out

    def close(self) -> None:
        try:
            if getattr(self, "cdp", None):
                try:
                    self.cdp.send("Browser.close", timeout=5)
                except (CdpError, OSError):
                    pass
                self.cdp.close()
        finally:
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(10)
            shutil.rmtree(self.profile, ignore_errors=True)


class Tab(Browser):
    """Another tab of ``browser``. It shares the cookie jar, as a reviewer's second tab does; closing it closes
    only the tab."""

    def __init__(self, browser: Browser) -> None:
        self.cdp = browser.cdp
        self._open_page()

    def close(self) -> None:
        self.cdp.send("Target.closeTarget", {"targetId": self.target})


# The accessibility audit run in the page (read-only DOM inspection).
A11Y_AUDIT = """(() => {
  const problems = [];
  const ids = new Set();
  for (const el of document.querySelectorAll('[id]')) {
    if (ids.has(el.id)) problems.push('duplicate id ' + el.id);
    ids.add(el.id);
  }
  for (const el of document.querySelectorAll('input, select, textarea')) {
    const named = (el.labels && el.labels.length) || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby');
    if (!named) problems.push('unlabelled control ' + el.tagName + '#' + el.id);
  }
  for (const t of document.querySelectorAll('table')) {
    if (!t.querySelector('caption') || !t.querySelector('caption').textContent.trim()) problems.push('table without caption');
    for (const th of t.querySelectorAll('thead th')) if (th.getAttribute('scope') !== 'col') problems.push('column header without scope');
    if (!t.closest('[role=region][tabindex="0"]')) problems.push('table not in a keyboard-scrollable region');
  }
  for (const c of document.querySelectorAll('button, a[href]')) {
    if (!c.textContent.trim() && !c.getAttribute('aria-label')) problems.push('control without a name');
  }
  let last = 0;
  for (const h of document.querySelectorAll('main h1, main h2, main h3, main h4')) {
    const n = Number(h.tagName[1]);
    if (last && n > last + 1) problems.push('heading level skipped at ' + h.textContent);
    last = n;
  }
  if (document.querySelectorAll('h1').length !== 1) problems.push('page has ' + document.querySelectorAll('h1').length + ' h1');
  for (const attr of ['aria-labelledby', 'aria-describedby']) {
    for (const el of document.querySelectorAll('[' + attr + ']')) {
      for (const id of el.getAttribute(attr).split(/\\s+/).filter(Boolean)) {
        if (!document.getElementById(id)) problems.push('dangling ' + attr + ' ' + id);
      }
    }
  }
  if (!document.documentElement.lang) problems.push('no lang');
  return problems;
})()"""
