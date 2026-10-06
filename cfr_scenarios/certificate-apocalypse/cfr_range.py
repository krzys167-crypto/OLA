"""Certificate Apocalypse range: four TLS services, a monitor, and the metric computation.

Two ways to run the SAME services (one code path for the TLS server, the probe and the metrics):

  process mode (`up` / `serve`)    four servers on 127.0.0.1 in ONE process, ports chosen at start. Needs nothing but
                                   python3, openssl and curl.
  container mode (`init`, `service`, `monitor`)   one container per role under docker/compose.yaml: `init` makes the
                                   certificates and the start-of-run state, `api` `billing` `static` `admin` are one
                                   TLS server each, `monitor` probes them over the compose network. The ports are
                                   published on 127.0.0.1 only; break / fix / assert / metrics stay on the host.

Services
    api, billing   share state/certs/server.pem  -> the fault hits them
    static, admin  have their own certificates   -> collateral damage if the participant breaks the CA

The certificate is re-read on EVERY handshake, so replacing server.pem fixes the services without a restart (a
restart is possible and costs a penalty). A restart is OBSERVED, not only announced: every server instance answers
/health with a fresh `boot=` token, the monitor records it, and a changed token is a restart whoever caused it.

state/ files: ports.json, timeline.jsonl (one line per probe round), events.jsonl, run.json, ready; range.pid (process mode)
HONEST LIMITS: the participant and the range share a machine. Container mode separates the services from each other and
the monitor from the participant's shell, it does not make the host trustworthy (the independent witness is for that).
k3d / Kubernetes is not provided.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
SERVICES = ("api", "billing", "static", "admin")
AFFECTED = ("api", "billing")
UNAFFECTED = ("static", "admin")
PEM = {"api": "server.pem", "billing": "server.pem", "static": "static.pem", "admin": "admin.pem"}
VARIANTS = ("expired", "untrusted-chain", "wrong-san")
INTERVAL_S = 0.2
STABLE_S = 10.0


def host_for(seed: str) -> str:
    return f"svc-{(seed or 'local')[:6]}.range.test"


def now() -> float:
    return time.time()


def _append(path: Path, obj: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, sort_keys=True) + "\n")


def read_lines(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text("utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# ------------------------------------------------------------------ the TLS services
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):                                              # noqa: N802
        body = f"ok {self.server.svc_name} boot={self.server.boot}\n".encode()
        code = 200 if self.path == "/health" else 404
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):                                     # silence
        pass


class TlsServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, svc_name: str, pem: Path):
        super().__init__(addr, _Handler)
        self.svc_name, self.pem = svc_name, pem
        self.boot = secrets.token_hex(4)                          # new for every server instance: a restart changes it

    def finish_request(self, request, client_address):
        try:
            request.settimeout(5)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(self.pem))                    # re-read per handshake: no restart needed
            tls = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError, ValueError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        except OSError:
            pass

    def handle_error(self, request, client_address):
        pass


_BOOT = re.compile(rb"\bboot=([0-9a-f]{1,32})\b")


def probe(port: int, host: str, ca: Path, timeout: float = 2.0, addr: str = "127.0.0.1") -> Dict[str, Any]:
    """One verified request. Hostname and chain are checked against `host` and the range CA, whatever `addr` is
    (a container name on the compose network, 127.0.0.1 for a published port)."""
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(f"GET /health HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = b""
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        ok = data.startswith(b"HTTP/1.0 200") or data.startswith(b"HTTP/1.1 200")
        out: Dict[str, Any] = {"ok": ok, "ms": round((time.monotonic() - t0) * 1000, 2), "err": "" if ok else "bad status"}
        boot = _BOOT.search(data.split(b"\r\n\r\n", 1)[-1]) if ok else None
        if boot:
            out["boot"] = boot.group(1).decode()
        return out
    except (ssl.SSLError, OSError) as exc:
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000, 2), "err": type(exc).__name__}


# ------------------------------------------------------------------ daemon
class Range:
    def __init__(self, state: Path, host: str):
        self.state, self.host = Path(state), host
        self.certs = self.state / "certs"
        self.servers: Dict[str, Tuple[TlsServer, threading.Thread]] = {}
        self.ports: Dict[str, int] = {}
        self.stop = threading.Event()

    def _gen(self, name: str) -> None:
        env = {**os.environ, "CERT_DIR": str(self.certs), "HOST": self.host}
        subprocess.run([str(HERE / "scripts" / "gen_good_cert.sh"), name], env=env, check=True, capture_output=True)

    def start_services(self) -> None:
        for svc in SERVICES:
            srv = TlsServer(("127.0.0.1", self.ports.get(svc, 0)), svc, self.certs / PEM[svc])
            th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            th.start()
            self.servers[svc] = (srv, th)
            self.ports[svc] = srv.server_address[1]

    def stop_services(self) -> None:
        for srv, th in self.servers.values():
            srv.shutdown()
            srv.server_close()
        self.servers.clear()

    def restart_services(self) -> None:
        self.stop_services()
        self.start_services()
        _append(self.state / "events.jsonl", {"t": now(), "event": "restart"})

    def serve(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        self.certs.mkdir(parents=True, exist_ok=True)
        for name in ("server", "static", "admin"):
            self._gen(name)
        self.start_services()
        (self.state / "ports.json").write_text(json.dumps(self.ports))
        (self.state / "range.pid").write_text(str(os.getpid()))
        signal.signal(signal.SIGTERM, lambda *a: self.stop.set())
        signal.signal(signal.SIGINT, lambda *a: self.stop.set())
        ca = self.certs / "ca.crt"
        _append(self.state / "events.jsonl", {"t": now(), "event": "up", "host": self.host,
                "ca_sha256": __import__("hashlib").sha256(ca.read_bytes()).hexdigest() if ca.is_file() else None})
        (self.state / "ready").write_text("1")
        timeline = self.state / "timeline.jsonl"
        while not self.stop.is_set():
            t = now()
            if (self.state / "restart.req").exists():
                (self.state / "restart.req").unlink()
                self.restart_services()
                (self.state / "ports.json").write_text(json.dumps(self.ports))
            res = {svc: probe(self.ports[svc], self.host, self.certs / "ca.crt") for svc in SERVICES}
            _append(timeline, {"t": t, "results": res})
            self.stop.wait(INTERVAL_S)
        self.stop_services()
        _append(self.state / "events.jsonl", {"t": now(), "event": "down"})


# ------------------------------------------------------------------ metrics (pure)
def _p95(values: List[float]) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, max(0, math.ceil(0.95 * len(v)) - 1))]


def _observed_restarts(rounds: List[Dict[str, Any]]) -> int:
    """The largest number of boot-token changes any single service showed between two successful probes."""
    last: Dict[str, str] = {}
    changes: Dict[str, int] = {}
    for r in rounds:
        for svc, p in r["results"].items():
            boot = p.get("boot") if isinstance(p, dict) else None
            if not isinstance(boot, str) or not boot:
                continue
            if svc in last and last[svc] != boot:
                changes[svc] = changes.get(svc, 0) + 1
            last[svc] = boot
    return max(changes.values(), default=0)


def compute_metrics(timeline: List[Dict[str, Any]], events: List[Dict[str, Any]], *, stable_s: float = STABLE_S
                    ) -> Optional[Dict[str, Any]]:
    """Metrics from what was OBSERVED. None when there is nothing to measure or no fault was injected.

    availability    verified probes that succeeded / all probes (all services, whole run)
    latency_p95_ms  95th percentile of successful probes
    mttr_s          from the injection to the start of the first window of `stable_s` seconds in which EVERY service
                    was healthy in every probe round; None = never recovered (or the stable window never completed)
    blast_radius    UNAFFECTED services (static, admin) that failed at least once after the injection: a fix that
                    breaks something else (e.g. regenerating the CA) is paid for here
    restarts        the most often any ONE service was restarted: the larger of the announced `restart` events and the
                    boot-token changes the probes observed (a restart by hand counts, announcing it is not required)
    downtime_s      time during which at least one service failed (rounds are integrated up to the next round)
    """
    inj = [e["t"] for e in events if e.get("event") == "fault_injected"]
    rounds = sorted((r for r in timeline if isinstance(r.get("results"), dict) and set(r["results"]) >= set(SERVICES)),
                    key=lambda r: r["t"])
    if not inj or len(rounds) < 2:
        return None
    t0 = min(inj)
    flat = [(svc, p) for r in rounds for svc, p in r["results"].items()]
    availability = sum(1 for _, p in flat if p["ok"]) / len(flat)
    latency = _p95([p["ms"] for _, p in flat if p["ok"]])
    after = [r for r in rounds if r["t"] >= t0]
    collateral = {svc for r in after for svc in UNAFFECTED if not r["results"][svc]["ok"]}
    downtime = 0.0
    for a, b in zip(rounds, rounds[1:]):
        if any(not p["ok"] for p in a["results"].values()):
            downtime += b["t"] - a["t"]
    mttr = None
    ok_rounds = [all(p["ok"] for p in r["results"].values()) for r in after]
    i = 0
    while i < len(after):
        if ok_rounds[i]:
            j = i
            while j + 1 < len(after) and ok_rounds[j + 1]:
                j += 1
            if after[j]["t"] - after[i]["t"] >= stable_s:
                mttr = after[i]["t"] - t0
                break
            i = j + 1
        else:
            i += 1
    restarts = max(sum(1 for e in events if e.get("event") == "restart"), _observed_restarts(rounds))
    return {"availability": round(availability, 6), "latency_p95_ms": round(latency, 3),
            "mttr_s": None if mttr is None else round(mttr, 3), "blast_radius": len(collateral),
            "restarts": restarts, "downtime_s": round(downtime, 3)}


# ------------------------------------------------------------------ CLI
def _state(a) -> Path:
    return Path(a.state)


def cmd_up(a) -> int:
    st = _state(a)
    run = json.loads((st / "run.json").read_text()) if (st / "run.json").is_file() else {}
    host = host_for(run.get("seed", ""))
    if (st / "range.pid").is_file():
        print("range already running (state/range.pid)", file=sys.stderr)
        return 1
    for f in ("timeline.jsonl", "events.jsonl", "ready", "ports.json"):
        (st / f).unlink(missing_ok=True)
    st.mkdir(parents=True, exist_ok=True)
    log = open(st / "range.log", "ab")
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--state", str(st), "serve", "--host", host],
                     stdout=log, stderr=log, start_new_session=True)
    for _ in range(200):
        if (st / "ready").exists() and (st / "timeline.jsonl").exists():
            print(f"range up: host={host} ports={(st / 'ports.json').read_text()}")
            return 0
        time.sleep(0.1)
    print("range did not become ready; see state/range.log", file=sys.stderr)
    return 1


def cmd_serve(a) -> int:
    Range(Path(a.state), a.host).serve()
    return 0


def cmd_break(a) -> int:
    st = _state(a)
    run = json.loads((st / "run.json").read_text()) if (st / "run.json").is_file() else {}
    variant = a.variant or run.get("variant") or "expired"
    if variant not in VARIANTS:
        print(f"unknown variant {variant!r}", file=sys.stderr)
        return 2
    host = host_for(run.get("seed", ""))
    env = {**os.environ, "CERT_DIR": str(st / "certs"), "HOST": host}
    subprocess.run([str(HERE / "scripts" / "gen_bad_cert.sh"), variant], env=env, check=True)
    _append(st / "events.jsonl", {"t": now(), "event": "fault_injected", "variant_sha256": __import__("hashlib")
            .sha256(variant.encode()).hexdigest()})
    return 0


def cmd_restart(a) -> int:
    (_state(a) / "restart.req").write_text("1")
    return 0


def cmd_down(a) -> int:
    st = _state(a)
    pid_file = st / "range.pid"
    if pid_file.is_file():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        for _ in range(50):
            if any(e.get("event") == "down" for e in read_lines(st / "events.jsonl")):
                break
            time.sleep(0.1)
        pid_file.unlink(missing_ok=True)
    return 0


def cmd_host(a) -> int:
    st = _state(a)
    run = json.loads((st / "run.json").read_text()) if (st / "run.json").is_file() else {}
    print(host_for(run.get("seed", "")))
    return 0


def cmd_metrics(a) -> int:
    st = _state(a)
    m = compute_metrics(read_lines(st / "timeline.jsonl"), read_lines(st / "events.jsonl"), stable_s=a.stable_s)
    print(json.dumps(m, indent=2) if m else "UNKNOWN: nothing to measure (no fault injected or no probes)")
    return 0 if m else 3


# ------------------------------------------------------------------ container roles (docker/compose.yaml)
# The same server, probe and metrics as process mode; what changes is who starts them and how they reach each other.
def _port(text: str) -> int:
    n = int(text)
    if not 1 <= n <= 65535:
        raise ValueError(f"port out of range: {text}")
    return n


def _target(text: str) -> Tuple[str, int]:
    addr, sep, port = text.rpartition(":")
    if not sep or not addr:
        raise ValueError(f"expected <address>:<port>, got {text!r}")
    return addr, _port(port)


def parse_map(text: str, what: str, parse) -> Dict[str, Any]:
    """`api=18441,billing=18442,static=18443,admin=18444` -> {name: parse(value)}; exactly the four services, once each."""
    out: Dict[str, Any] = {}
    for item in (x.strip() for x in text.split(",")):
        if not item:
            continue
        name, sep, value = item.partition("=")
        if not sep or name not in SERVICES or name in out:
            raise ValueError(f"{what}: bad or repeated entry {item!r}")
        out[name] = parse(value)
    if set(out) != set(SERVICES):
        raise ValueError(f"{what} must name exactly: {', '.join(SERVICES)}")
    return out


def cmd_init(a) -> int:
    """Role `init`: runs once per `docker compose up`. Leaves the state a fresh process-mode `up` leaves: new leaf
    certificates (the CA is kept when it exists: it is never regenerated), ports.json, the `up` event; no timeline."""
    try:
        ports = parse_map(a.ports, "--ports", _port)
    except ValueError as exc:
        print(f"init: {exc}", file=sys.stderr)
        return 2
    st = _state(a)
    st.mkdir(parents=True, exist_ok=True)
    for f in ("timeline.jsonl", "events.jsonl", "ready", "ports.json"):
        (st / f).unlink(missing_ok=True)
    rg = Range(st, a.host)
    rg.certs.mkdir(parents=True, exist_ok=True)
    try:
        for name in ("server", "static", "admin"):
            rg._gen(name)
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        print(f"init: certificate generation failed: {exc} {detail.decode(errors='replace')[:400]}", file=sys.stderr)
        return 1
    (st / "ports.json").write_text(json.dumps(ports))
    ca = rg.certs / "ca.crt"
    _append(st / "events.jsonl", {"t": now(), "event": "up", "host": a.host,
                                  "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest() if ca.is_file() else None})
    print(f"init: host={a.host} ports={json.dumps(ports)}", flush=True)
    return 0


def cmd_service(a) -> int:
    """Role `api` | `billing` | `static` | `admin`: one TLS server, in the foreground, until SIGTERM."""
    if a.name not in SERVICES:
        print(f"service: unknown service {a.name!r}", file=sys.stderr)
        return 2
    srv = TlsServer((a.bind, a.port), a.name, Path(a.state) / "certs" / PEM[a.name])

    def _stop(*_):                                                # shutdown() must not run in the serving thread
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"service {a.name} boot={srv.boot} on {a.bind}:{a.port}", flush=True)
    srv.serve_forever(poll_interval=0.1)
    srv.server_close()
    return 0


def cmd_monitor(a) -> int:
    """Role `monitor`: probes every service, verified (chain + hostname), every INTERVAL_S, and appends a timeline round.
    `ready` appears after the first round in which all four answered."""
    try:
        targets = parse_map(a.targets, "--targets", _target)
    except ValueError as exc:
        print(f"monitor: {exc}", file=sys.stderr)
        return 2
    st = _state(a)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    ca = st / "certs" / "ca.crt"
    print(f"monitor: host={a.host} targets={a.targets}", flush=True)
    ready = False
    while not stop.is_set():
        t = now()
        res = {svc: probe(port, a.host, ca, addr=addr) for svc, (addr, port) in targets.items()}
        _append(st / "timeline.jsonl", {"t": t, "results": res})
        if not ready and all(p["ok"] for p in res.values()):
            (st / "ready").write_text("1")
            ready = True
        stop.wait(INTERVAL_S)
    _append(st / "events.jsonl", {"t": now(), "event": "down"})
    return 0


def cmd_wait(a) -> int:
    """Host side: block until the range is observed healthy (ready + the last three rounds all healthy), or time out."""
    st = _state(a)
    deadline = time.monotonic() + a.timeout
    while time.monotonic() < deadline:
        rounds = [r for r in read_lines(st / "timeline.jsonl") if isinstance(r.get("results"), dict)]
        healthy = len(rounds) >= 3 and all(p.get("ok") for r in rounds[-3:] for p in r["results"].values())
        if (st / "ready").exists() and (st / "ports.json").is_file() and healthy:
            print(f"range up: ports={(st / 'ports.json').read_text()}")
            return 0
        time.sleep(0.5)
    print("range did not become healthy in time; see: docker compose logs", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cfr_range.py")
    p.add_argument("--state", default="state")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("up").set_defaults(fn=cmd_up)
    s = sub.add_parser("serve"); s.add_argument("--host", required=True); s.set_defaults(fn=cmd_serve)
    b = sub.add_parser("break"); b.add_argument("--variant"); b.set_defaults(fn=cmd_break)
    sub.add_parser("restart").set_defaults(fn=cmd_restart)
    sub.add_parser("down").set_defaults(fn=cmd_down)
    sub.add_parser("host").set_defaults(fn=cmd_host)
    m = sub.add_parser("metrics"); m.add_argument("--stable-s", type=float, default=STABLE_S); m.set_defaults(fn=cmd_metrics)
    i = sub.add_parser("init"); i.add_argument("--host", required=True); i.add_argument("--ports", required=True)
    i.set_defaults(fn=cmd_init)
    v = sub.add_parser("service"); v.add_argument("--name", required=True); v.add_argument("--bind", default="0.0.0.0")
    v.add_argument("--port", type=int, default=8443); v.set_defaults(fn=cmd_service)
    o = sub.add_parser("monitor"); o.add_argument("--host", required=True); o.add_argument("--targets", required=True)
    o.set_defaults(fn=cmd_monitor)
    w = sub.add_parser("wait"); w.add_argument("--timeout", type=float, default=120.0); w.set_defaults(fn=cmd_wait)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
