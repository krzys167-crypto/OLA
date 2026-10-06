"""Certificate Apocalypse in containers: the roles (init, service, monitor), the observed restart, and the files that
define the container range (compose.yaml, Dockerfile, Makefile, the CI workflow, ci_check.py).

No Docker is needed or used here: the container ROLES are plain `cfr_range.py` subcommands, so the tests run them as
processes on 127.0.0.1 and drive the same break / fix / assert / metrics a participant would. What these tests CANNOT show
is that Docker accepts compose.yaml and the image builds: that is measured by .github/workflows/cfr-docker.yml.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "cfr_scenarios" / "certificate-apocalypse"
sys.path.insert(0, str(DIR))
import cfr_range as rng  # noqa: E402

COMPOSE = DIR / "docker" / "compose.yaml"
DOCKERFILE = DIR / "docker" / "Dockerfile"
DOCKERIGNORE = DIR / ".dockerignore"
MAKEFILE = DIR / "Makefile"
WORKFLOW = ROOT / ".github" / "workflows" / "cfr-docker.yml"
CHECK = DIR / "docker" / "ci_check.py"
MANIFEST = json.loads((DIR / "manifest.json").read_text())

TOOLS = pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("curl")), reason="needs openssl and curl")


# ------------------------------------------------------------------ helpers
def _free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _cli(state, *args, **kw):
    return subprocess.run([sys.executable, str(DIR / "cfr_range.py"), "--state", str(state), *args],
                          capture_output=True, text=True, timeout=60, **kw)


class Roles:
    """docker/compose.yaml's roles as processes: init once, one `service` per name, one `monitor`."""

    def __init__(self, tmp_path, seed="abcdef"):
        self.state = tmp_path / "state"
        self.state.mkdir()
        self.seed = seed
        (self.state / "run.json").write_text(json.dumps({"seed": seed, "variant": "expired"}))
        self.host = rng.host_for(seed)
        self.ports = dict(zip(rng.SERVICES, _free_ports(4)))
        self.procs = {}

    @property
    def ports_arg(self):
        return ",".join(f"{k}={v}" for k, v in self.ports.items())

    def init(self):
        return _cli(self.state, "init", "--host", self.host, "--ports", self.ports_arg)

    def start_service(self, name):
        self.procs[name] = subprocess.Popen(
            [sys.executable, str(DIR / "cfr_range.py"), "--state", str(self.state), "service", "--name", name,
             "--bind", "127.0.0.1", "--port", str(self.ports[name])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self.procs[name]

    def start_monitor(self):
        targets = ",".join(f"{k}=127.0.0.1:{v}" for k, v in self.ports.items())
        self.procs["monitor"] = subprocess.Popen(
            [sys.executable, str(DIR / "cfr_range.py"), "--state", str(self.state), "monitor", "--host", self.host,
             "--targets", targets], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self.procs["monitor"]

    def stop(self, name, wait=5):
        proc = self.procs.pop(name)
        proc.send_signal(signal.SIGTERM)
        return proc.wait(timeout=wait)

    def close(self):
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    def assertions(self, stable_s=2):
        env = {**os.environ, "STATE": str(self.state), "HOST": self.host, "STABLE_S": str(stable_s)}
        out = subprocess.run([str(DIR / "assertions.sh")], capture_output=True, text=True, env=env, timeout=120).stdout
        return {r["id"]: r["result"] for r in map(json.loads, out.splitlines())}

    def fix(self):
        env = {"PATH": os.environ["PATH"], "CERT_DIR": str(self.state / "certs"), "HOST": self.host}
        return subprocess.run([str(DIR / "scripts" / "gen_good_cert.sh")], capture_output=True, text=True, env=env)


@pytest.fixture
def roles(tmp_path):
    r = Roles(tmp_path)
    yield r
    r.close()


def _wait_for(predicate, timeout=15.0, step=0.1):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(step)
    return False


def _rounds(state):
    return [r for r in rng.read_lines(state / "timeline.jsonl") if isinstance(r.get("results"), dict)]


# ------------------------------------------------------------------ the argument grammar
def test_the_port_and_target_maps_name_exactly_the_four_services_once():
    ok = rng.parse_map("api=1,billing=2,static=3,admin=65535", "--ports", rng._port)
    assert ok == {"api": 1, "billing": 2, "static": 3, "admin": 65535}
    for bad in ("", "api=1,billing=2,static=3",                          # one missing
                "api=1,billing=2,static=3,admin=4,api=5",                # repeated
                "api=1,billing=2,static=3,admin=4,db=5",                 # unknown service
                "api=1,billing=2,static=3,admin",                        # no value
                "api=1,billing=2,static=3,admin=0", "api=1,billing=2,static=3,admin=65536",
                "api=1,billing=2,static=3,admin=x"):
        with pytest.raises(ValueError):
            rng.parse_map(bad, "--ports", rng._port)
    assert rng._target("api:8443") == ("api", 8443) and rng._target("127.0.0.1:1") == ("127.0.0.1", 1)
    for bad in ("api", ":8443", "api:", "api:70000"):
        with pytest.raises(ValueError):
            rng._target(bad)


def test_init_and_monitor_refuse_a_bad_map_with_status_2_before_touching_anything(tmp_path):
    state = tmp_path / "state"
    r = _cli(state, "init", "--host", "svc-x.range.test", "--ports", "api=1")
    assert r.returncode == 2 and "init:" in r.stderr and not state.exists(), (r.returncode, r.stderr)
    r = _cli(state, "monitor", "--host", "svc-x.range.test", "--targets", "api=api")
    assert r.returncode == 2 and "monitor:" in r.stderr, (r.returncode, r.stderr)
    assert _cli(state, "service", "--name", "db").returncode == 2


# ------------------------------------------------------------------ init
@TOOLS
def test_init_leaves_the_start_of_run_state_and_a_second_init_keeps_the_ca_but_renews_the_leaves(tmp_path):
    r = Roles(tmp_path)
    assert r.init().returncode == 0
    st = r.state
    for f in ("ca.crt", "ca.key", "server.pem", "static.pem", "admin.pem"):
        assert (st / "certs" / f).is_file(), f
    assert json.loads((st / "ports.json").read_text()) == r.ports
    events = rng.read_lines(st / "events.jsonl")
    assert [e["event"] for e in events] == ["up"] and events[0]["host"] == r.host
    assert events[0]["ca_sha256"] == hashlib.sha256((st / "certs" / "ca.crt").read_bytes()).hexdigest()
    assert not (st / "timeline.jsonl").exists() and not (st / "ready").exists()      # the monitor makes those
    ca1, srv1 = (st / "certs" / "ca.crt").read_bytes(), (st / "certs" / "server.pem").read_bytes()
    # leftovers of a previous run: a broken certificate, a timeline, a ready marker, an old fault event
    (st / "certs" / "server.pem").write_text("BROKEN")
    (st / "timeline.jsonl").write_text('{"t": 1}\n')
    (st / "ready").write_text("1")
    rng._append(st / "events.jsonl", {"t": 1.0, "event": "fault_injected"})
    assert r.init().returncode == 0
    assert (st / "certs" / "ca.crt").read_bytes() == ca1                               # the CA is never regenerated
    assert (st / "certs" / "server.pem").read_bytes() not in (b"BROKEN", srv1)         # a fresh, valid leaf
    assert not (st / "timeline.jsonl").exists() and not (st / "ready").exists()
    assert [e["event"] for e in rng.read_lines(st / "events.jsonl")] == ["up"]         # no stale fault_injected


def test_init_without_openssl_fails_loudly_and_writes_no_ports_json(tmp_path):
    r = Roles(tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    out = subprocess.run([sys.executable, str(DIR / "cfr_range.py"), "--state", str(r.state), "init", "--host", r.host,
                          "--ports", r.ports_arg], capture_output=True, text=True, env={"PATH": str(empty)}, timeout=60)
    assert out.returncode == 1 and "certificate generation failed" in out.stderr, (out.returncode, out.stderr)
    assert not (r.state / "ports.json").exists() and not any(e.get("event") == "up" for e in rng.read_lines(r.state / "events.jsonl"))


# ------------------------------------------------------------------ the roles, run as processes
@TOOLS
def test_monitor_is_ready_only_after_a_round_in_which_all_four_answered(roles):
    assert roles.init().returncode == 0
    roles.start_monitor()                                                   # nothing listens yet
    assert _wait_for(lambda: len(_rounds(roles.state)) >= 3, 10)
    assert not (roles.state / "ready").exists()
    assert not any(p["ok"] for r in _rounds(roles.state) for p in r["results"].values())
    for name in rng.SERVICES[:3]:
        roles.start_service(name)
    time.sleep(1.0)
    assert not (roles.state / "ready").exists()                             # three of four is not ready
    roles.start_service(rng.SERVICES[3])
    assert _wait_for(lambda: (roles.state / "ready").exists(), 10)
    assert _cli(roles.state, "wait", "--timeout", "10").returncode == 0


@TOOLS
def test_wait_gives_up_with_status_1_when_the_range_never_becomes_healthy(roles):
    assert roles.init().returncode == 0
    roles.start_monitor()
    r = _cli(roles.state, "wait", "--timeout", "2")
    assert r.returncode == 1 and "did not become healthy" in r.stderr, (r.returncode, r.stderr)


def test_wait_needs_ready_the_ports_and_the_last_three_rounds_all_healthy(tmp_path):
    def state(n, *, ready=True, ports=True, last=()):
        d = tmp_path / f"s{n}"
        d.mkdir()
        if ready:
            (d / "ready").write_text("1")
        if ports:
            (d / "ports.json").write_text(json.dumps({s: 1 for s in rng.SERVICES}))
        for i, ok in enumerate(last):
            rng._append(d / "timeline.jsonl", {"t": float(i), "results": {s: {"ok": ok, "ms": 1.0} for s in rng.SERVICES}})
        return d

    def wait(d):
        return _cli(d, "wait", "--timeout", "0.6").returncode

    assert wait(state(1, last=(True, True, True))) == 0
    assert wait(state(2, last=(False, True, True, True))) == 0                  # an old failure outside the last three is history
    assert wait(state(3, last=(True, True, False))) == 1                        # it broke again right now
    assert wait(state(4, last=(False, True, True))) == 1                        # the third round back is not healthy
    assert wait(state(5, last=(True, True))) == 1                               # two rounds are not enough
    assert wait(state(6, ready=False, last=(True, True, True))) == 1
    assert wait(state(7, ports=False, last=(True, True, True))) == 1
    one_bad = state(8, last=(True, True, True))                                 # a single failed probe of one service counts
    rng._append(one_bad / "timeline.jsonl", {"t": 9.0, "results": {**{s: {"ok": True, "ms": 1.0} for s in rng.SERVICES},
                                                                  "admin": {"ok": False, "ms": 1.0, "err": "x"}}})
    assert wait(one_bad) == 1


@TOOLS
def test_a_participant_run_against_the_container_roles_break_fix_assert_metrics_and_a_hand_restart(roles):
    assert roles.init().returncode == 0
    for name in rng.SERVICES:
        roles.start_service(name)
    roles.start_monitor()
    assert _cli(roles.state, "wait", "--timeout", "20").returncode == 0
    base = roles.assertions()
    assert set(base.values()) == {"pass"} and len(base) == 7, base                   # nothing is broken at the start
    boots = {svc: p["boot"] for svc, p in _rounds(roles.state)[-1]["results"].items()}
    assert len(set(boots.values())) == 4 and all(re.fullmatch(r"[0-9a-f]{8}", b) for b in boots.values()), boots

    assert _cli(roles.state, "break").returncode == 0                               # variant of run.json: expired
    time.sleep(1.5)
    broken = roles.assertions(stable_s=1)
    assert broken["x509_not_expired"] == "fail" and broken["ca_untouched"] == "pass", broken
    # only the shared certificate is hit: static and admin keep answering
    last = _rounds(roles.state)[-1]["results"]
    assert not last["api"]["ok"] and not last["billing"]["ok"] and last["static"]["ok"] and last["admin"]["ok"], last

    assert roles.fix().returncode == 0
    time.sleep(3.0)                                                                  # > stable window below
    fixed = roles.assertions()
    assert set(fixed.values()) == {"pass"}, fixed
    m = json.loads(_cli(roles.state, "metrics", "--stable-s", "2").stdout)
    assert m["mttr_s"] is not None and m["blast_radius"] == 0 and m["restarts"] == 0 and m["availability"] < 1, m
    assert {svc: p["boot"] for svc, p in _rounds(roles.state)[-1]["results"].items()} == boots   # nobody restarted

    # the participant restarts api by hand: nothing announces it, the boot token does
    assert roles.stop("api") == 0                                                    # SIGTERM -> clean exit, not a kill
    time.sleep(0.6)
    roles.start_service("api")
    assert _wait_for(lambda: _rounds(roles.state)[-1]["results"]["api"].get("boot") not in (None, boots["api"]), 10)
    time.sleep(0.5)
    after = json.loads(_cli(roles.state, "metrics", "--stable-s", "2").stdout)
    assert after["restarts"] == 1, after
    assert not any(e.get("event") == "restart" for e in rng.read_lines(roles.state / "events.jsonl"))
    assert roles.stop("monitor") == 0
    assert rng.read_lines(roles.state / "events.jsonl")[-1]["event"] == "down"


@TOOLS
def test_a_service_stops_on_sigterm_within_a_second(roles):
    assert roles.init().returncode == 0
    proc = roles.start_service("api")
    assert _wait_for(lambda: rng.probe(roles.ports["api"], roles.host, roles.state / "certs" / "ca.crt")["ok"], 10)
    t0 = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=5) == 0 and time.monotonic() - t0 < 2.0              # docker stop would not need its SIGKILL
    roles.procs.pop("api")


@TOOLS
def test_the_probe_checks_the_host_name_whatever_address_it_connects_to(roles):
    assert roles.init().returncode == 0
    roles.start_service("static")
    ca = roles.state / "certs" / "ca.crt"
    assert _wait_for(lambda: rng.probe(roles.ports["static"], roles.host, ca)["ok"], 10)
    by_name = rng.probe(roles.ports["static"], roles.host, ca, addr="localhost")      # like `api:8443` on the compose network
    assert by_name["ok"] and re.fullmatch(r"[0-9a-f]{8}", by_name["boot"]), by_name
    wrong = rng.probe(roles.ports["static"], "svc-other.range.test", ca, addr="localhost")
    assert not wrong["ok"] and "boot" not in wrong, wrong                             # a certificate for another host is no pass


# ------------------------------------------------------------------ restarts are observed
def _round(t, **boots):
    return {"t": t, "results": {s: ({"ok": True, "ms": 5.0, "boot": boots[s]} if boots.get(s) else
                                    {"ok": True, "ms": 5.0}) for s in rng.SERVICES}}


def _metrics(rounds, events=()):
    return rng.compute_metrics(rounds, [{"t": 0.5, "event": "fault_injected"}, *events], stable_s=1.0)


def test_a_changed_boot_token_is_a_restart_and_a_stable_one_is_not():
    same = [_round(float(i), api="a1", billing="b1", static="c1", admin="d1") for i in range(6)]
    assert _metrics(same)["restarts"] == 0
    one = same[:3] + [_round(float(i), api="a2", billing="b1", static="c1", admin="d1") for i in range(3, 6)]
    assert _metrics(one)["restarts"] == 1


def test_restarts_are_the_most_often_any_one_service_restarted_not_a_sum():
    rounds = [_round(0.0, api="a1", billing="b1", static="c1", admin="d1"), _round(1.0, api="a2", billing="b2", static="c1", admin="d1"),
              _round(2.0, api="a3", billing="b2", static="c1", admin="d1"), _round(3.0, api="a3", billing="b2", static="c1", admin="d1")]
    assert _metrics(rounds)["restarts"] == 2                                          # api twice, billing once


def test_announced_and_observed_restarts_are_not_added_together():
    rounds = [_round(0.0, api="a1", billing="b1", static="c1", admin="d1"), _round(1.0, api="a2", billing="b1", static="c1", admin="d1"),
              _round(2.0, api="a2", billing="b1", static="c1", admin="d1")]
    both = _metrics(rounds, [{"t": 0.9, "event": "restart"}])
    assert both["restarts"] == 1                                                      # the same restart seen twice is one
    assert _metrics(rounds[:1] + rounds[2:], [{"t": 0.9, "event": "restart"}, {"t": 1.1, "event": "restart"}])["restarts"] == 2


def test_probes_without_a_token_and_failed_probes_make_no_phantom_restart():
    r = [_round(0.0, api="a1"), _round(1.0), _round(2.0, api="a1"), _round(3.0, api="a1")]          # a round without tokens
    assert _metrics(r)["restarts"] == 0
    failing = _round(1.0, api="a1", billing="b1", static="c1", admin="d1")
    failing["results"]["api"] = {"ok": False, "ms": 2.0, "err": "TimeoutError"}                 # failed: no token, no change
    r = [_round(0.0, api="a1", billing="b1", static="c1", admin="d1"), failing,
         _round(2.0, api="a1", billing="b1", static="c1", admin="d1"), _round(3.0, api="a1", billing="b1", static="c1", admin="d1")]
    assert _metrics(r)["restarts"] == 0


def test_the_health_body_carries_a_fresh_token_per_server_instance(tmp_path):
    a = rng.TlsServer(("127.0.0.1", 0), "api", tmp_path / "x.pem")
    b = rng.TlsServer(("127.0.0.1", 0), "api", tmp_path / "x.pem")
    try:
        assert re.fullmatch(r"[0-9a-f]{8}", a.boot) and a.boot != b.boot
    finally:
        a.server_close()
        b.server_close()


# ------------------------------------------------------------------ compose.yaml
def _yaml():
    """PyYAML is not in requirements.txt (it is not a runtime dependency). The structure checks need it: the dedicated CI job
    (.github/workflows/cfr-docker.yml) installs it and fails if any test of this module was skipped."""
    return pytest.importorskip("yaml", reason="PyYAML missing: cfr-docker.yml installs it and forbids skips")


def _compose():
    return _yaml().safe_load(COMPOSE.read_text(encoding="utf-8"))


def _default(text, var):
    m = re.search(r"\$\{" + var + r":-(\d+)\}", text)
    assert m, (var, text)
    return int(m.group(1))


def test_compose_defines_the_six_roles_from_one_image_and_only_init_builds_it():
    svcs = _compose()["services"]
    assert list(svcs) == ["init", "api", "billing", "static", "admin", "monitor"]
    assert {s["image"] for s in svcs.values()} == {"cfr-range:local"}
    assert [n for n, s in svcs.items() if "build" in s] == ["init"]
    assert all(s["pull_policy"] == "never" for s in svcs.values())                    # never pulls "cfr-range" from a registry


def test_every_role_runs_unprivileged_read_only_with_no_capabilities_and_no_host_access():
    for name, s in _compose()["services"].items():
        assert s["read_only"] is True and s["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in s["security_opt"], name
        assert "CFR_UID" in s["user"] and "CFR_GID" in s["user"] and not s["user"].startswith("0"), (name, s["user"])
        assert s["restart"] == "no" and s["mem_limit"] and s["pids_limit"], name
        for forbidden in ("privileged", "cap_add", "network_mode", "pid", "ipc", "devices", "sysctls"):
            assert forbidden not in s, (name, forbidden)
        for vol in s.get("volumes", []):
            assert "docker.sock" not in vol and not vol.startswith("/:"), (name, vol)
    assert "docker.sock" not in COMPOSE.read_text(encoding="utf-8")


def test_published_ports_are_loopback_only_and_match_what_init_writes_to_ports_json():
    c = _compose()
    published = {}
    for name in rng.SERVICES:
        (port,) = c["services"][name]["ports"]
        m = re.fullmatch(r"127\.0\.0\.1:\$\{CFR_PORT_(\w+):-(\d+)\}:8443", port)
        assert m and m.group(1) == name.upper(), (name, port)                            # never 0.0.0.0, never a bare port
        published[name] = int(m.group(2))
    assert len(set(published.values())) == 4
    ports_arg = c["services"]["init"]["command"][c["services"]["init"]["command"].index("--ports") + 1]
    assert rng.parse_map(re.sub(r"\$\{\w+:-(\d+)\}", r"\1", ports_arg), "--ports", rng._port) == published   # same defaults


def test_the_services_mount_the_certificate_directory_read_only_and_nothing_else():
    c = _compose()["services"]
    for name in rng.SERVICES:
        (vol,) = c[name]["volumes"]
        assert vol.endswith("/certs:/state/certs:ro"), (name, vol)                       # a directory: rename-replace is seen
        assert not vol.endswith(".pem:ro") and "/certs/" not in vol
        assert c[name]["depends_on"]["init"]["condition"] == "service_completed_successfully"
        cmd = c[name]["command"]
        assert cmd[cmd.index("--name") + 1] == name
    assert c["init"]["volumes"] == ['${CFR_STATE:?run through make docker-up}:/state']      # only init and monitor write state
    assert c["monitor"]["volumes"] == c["init"]["volumes"]


def test_the_monitor_probes_all_four_services_by_name_on_the_container_port_after_they_started():
    m = _compose()["services"]["monitor"]
    cmd = m["command"]
    assert rng.parse_map(cmd[cmd.index("--targets") + 1], "--targets", rng._target) == {s: (s, 8443) for s in rng.SERVICES}
    assert set(m["depends_on"]) == {"init", *rng.SERVICES}
    assert m["depends_on"]["init"]["condition"] == "service_completed_successfully"
    assert all(m["depends_on"][s]["condition"] == "service_started" for s in rng.SERVICES)


def _docker_compose_available():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


DOCKER_COMPOSE = pytest.mark.skipif(not _docker_compose_available(), reason="needs the docker CLI with the compose plugin "
                                    "(no daemon: `config` only parses and resolves; the CI job has it)")


def _config(**env):
    base = {**os.environ, "CFR_STATE": "/tmp/cfr-state-for-config", "CFR_UID": "1001", "CFR_GID": "118", "CFR_HOST": "svc-abc123.range.test"}
    for k in [k for k in base if k.startswith("CFR_PORT_")]:
        del base[k]
    r = subprocess.run(["docker", "compose", "-f", str(COMPOSE), "config", "--format", "json"], capture_output=True, text=True,
                       env={**base, **env}, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@DOCKER_COMPOSE
def test_docker_compose_itself_accepts_the_file_and_resolves_it_the_way_the_tests_assume():
    cfg = _config()
    assert list(cfg["services"]) == ["admin", "api", "billing", "init", "monitor", "static"] or set(cfg["services"]) == {
        "init", "api", "billing", "static", "admin", "monitor"}
    for name in rng.SERVICES:
        (port,) = cfg["services"][name]["ports"]
        assert port["host_ip"] == "127.0.0.1" and port["target"] == 8443, (name, port)         # as Docker resolves it, not as text
        assert [v["read_only"] for v in cfg["services"][name]["volumes"]] == [True]
        assert cfg["services"][name]["user"] == "1001:118" and cfg["services"][name]["read_only"] is True
    assert cfg["services"]["init"]["build"]["dockerfile"] == "docker/Dockerfile"
    assert Path(cfg["services"]["init"]["build"]["context"]) == DIR                           # `..` from docker/ is the scenario dir
    assert (DIR / cfg["services"]["init"]["build"]["dockerfile"]).is_file()


@DOCKER_COMPOSE
def test_changing_a_published_port_changes_what_init_writes_to_ports_json_in_the_same_run():
    def view(cfg):
        init = cfg["services"]["init"]["command"]
        ports = rng.parse_map(init[init.index("--ports") + 1], "--ports", rng._port)
        published = {n: int(cfg["services"][n]["ports"][0]["published"]) for n in rng.SERVICES}
        return ports, published

    assert view(_config()) == ({"api": 18441, "billing": 18442, "static": 18443, "admin": 18444},) * 2
    ports, published = view(_config(CFR_PORT_API="29441", CFR_PORT_ADMIN="29444"))
    assert ports == published == {"api": 29441, "billing": 18442, "static": 18443, "admin": 29444}
    r = subprocess.run(["docker", "compose", "-f", str(COMPOSE), "config", "-q"], capture_output=True, text=True, timeout=60,
                       env={k: v for k, v in os.environ.items() if not k.startswith("CFR_")})
    assert r.returncode != 0 and "run through make docker-up" in r.stderr                      # no variables: refuses, does not guess


def test_the_image_has_exactly_what_the_roles_run_and_nothing_more():
    text = DOCKERFILE.read_text(encoding="utf-8")
    code = "\n".join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))      # instructions, no comments
    assert re.search(r"^FROM debian:13-slim$", code, re.M)                              # the base of the repository's own image
    assert ":latest" not in code and not re.search(r"^USER\b", code, re.M)              # the user comes from compose (host uid:gid)
    assert re.search(r"^ENTRYPOINT \[\"python3\", \"/opt/cfr/cfr_range\.py\"\]$", code, re.M)
    copies = re.findall(r"^COPY (\S+) ", code, re.M)
    assert copies == ["cfr_range.py", "scripts"], copies
    ignore = [l for l in DOCKERIGNORE.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    assert ignore == ["*", "!cfr_range.py", "!scripts"], ignore                          # nothing else enters the build context
    # every script cfr_range.py starts exists in scripts/ and is executable (the image keeps the mode)
    for name in re.findall(r'HERE / "scripts" / "([\w.]+)"', (DIR / "cfr_range.py").read_text(encoding="utf-8")):
        assert os.access(DIR / "scripts" / name, os.X_OK), name
    assert "openssl" in code and "python3" in code


# ------------------------------------------------------------------ Makefile
def _target(text, name):
    m = re.search(r"^" + re.escape(name) + r":(.*?)(?=^\S|\Z)", text, re.M | re.S)
    assert m, name
    return m.group(1)


def test_make_docker_targets_reset_first_precreate_the_state_and_wait_for_a_healthy_range():
    text = MAKEFILE.read_text(encoding="utf-8")
    assert ".PHONY: docker-up docker-restart docker-down docker-logs" in text
    env = re.search(r"^CFR_ENV\s*=(.*)$", text, re.M).group(1)
    for var in ("CFR_STATE=$(abspath $(STATE))", "CFR_UID=$$(id -u)", "CFR_GID=$$(id -g)", "CFR_HOST=$$($(PY) $(CD) host)"):
        assert var in env, var
    up = _target(text, "docker-up")
    lines = [l.strip() for l in up.splitlines() if l.strip()]
    assert [l.split()[0] for l in lines[:1]] == ["$(CFR_ENV)"] and " down " in lines[0]            # old containers first
    assert lines[1] == "mkdir -p $(STATE)/certs"                                    # created by the user, not by the daemon (root)
    assert "up -d --build --force-recreate" in lines[2]
    assert lines[3] == "$(PY) $(CD) wait --timeout 120"
    assert "restart --timeout 5 api billing" in _target(text, "docker-restart")
    assert "down --remove-orphans" in _target(text, "docker-down")
    # the participant's targets are the SAME in both modes
    for same in ("break", "fix", "assert", "metrics", "score"):
        assert f"{same}:" in text


# ------------------------------------------------------------------ the CI workflow
def _workflow():
    return _yaml().safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps():
    return {s.get("name"): s for s in _workflow()["jobs"]["cfr-docker"]["steps"]}


def test_the_workflow_is_unprivileged_pinned_and_has_no_secrets():
    text = WORKFLOW.read_text(encoding="utf-8")
    w = _workflow()
    assert w["permissions"] == {"contents": "read"}
    assert set(w[True]) == {"pull_request"}                                             # never pull_request_target
    for uses in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses), uses
    assert not re.search(r"\$\{\{\s*secrets\.", text) and "GITHUB_TOKEN" not in text                   # no secret is read
    assert re.search(r"K6_IMAGE: grafana/k6:\d+\.\d+\.\d+\b", text) and ":latest" not in text


def test_the_workflow_asserts_each_stage_of_the_incident_not_just_that_it_ran():
    steps = _steps()
    run = {name: s["run"] for name, s in steps.items() if "run" in s}
    joined = "\n".join(run.values())
    order = [i for i, s in enumerate(_workflow()["jobs"]["cfr-docker"]["steps"]) if "run" in s]
    assert order == sorted(order)
    assert "docker-up" in joined and "witness-up" in joined
    baseline = next(v for k, v in run.items() if k.startswith("Baseline"))
    assert "ci_check.py" in baseline and "all-pass" in baseline
    broken = next(v for k, v in run.items() if k.startswith("The fault is visible"))
    for want in ("x509_not_expired=fail", "health_stable_10s=fail", "ca_untouched=pass", "tls_handshake_ok=pass"):
        assert want in broken, want
    fixed = next(v for k, v in run.items() if k.startswith("Fix without touching the CA"))
    assert " fix" in fixed and "all-pass" in fixed and "STABLE_S" not in fixed          # the full 10 s window
    metrics = next(v for k, v in run.items() if k.startswith("Metrics of the incident"))
    for want in ("--recovered", "--blast-radius 0", "--restarts 0", "--max-availability"):
        assert want in metrics, want
    assert "witness" in next(v for k, v in run.items() if "independent witness" in k and "agrees" in k)
    restart = next(v for k, v in run.items() if k.startswith("A restart is OBSERVED"))
    assert "docker-restart" in restart and "--min-restarts 1" in restart
    k6 = next(v for k, v in run.items() if k.startswith("k6 load"))
    assert "SSL_CERT_FILE" in k6 and "--network host" in k6 and "--insecure" not in k6 and "insecure-skip" not in k6.lower()
    assert all(steps[n].get("if") == "always()" for n in ("Upload evidence", "Stop", "Container logs and state"))
    offline = steps["Offline tests of the container range (PyYAML installed, no test may be skipped)"]
    assert offline["if"] == "always()" and "tests/test_cfr_containers.py" in offline["run"] and "skipped" in offline["run"]
    assert "PyYAML==" in steps["Install the repository requirements (and PyYAML for the structure tests)"]["run"]
    assert steps["Annotate a failure with the container logs"]["if"] == "failure()"


def test_the_k6_script_no_longer_claims_to_be_unrun_and_verifies_tls():
    js = (DIR / "k6_load.js").read_text(encoding="utf-8")
    assert "NOT run" not in js and "cfr-docker.yml" in js and "SSL_CERT_FILE" in js
    assert "insecureSkipTLSVerify" not in js


# ------------------------------------------------------------------ ci_check.py
def _check(*args, env=None, cwd=None):
    return subprocess.run([sys.executable, str(CHECK), *args], capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})}, cwd=cwd)


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    return str(p)


def _assertions_file(tmp_path, **results):
    return _write(tmp_path, "a.jsonl", "".join(json.dumps({"id": k, "result": v}) + "\n" for k, v in results.items()))


ALL_IDS = MANIFEST["required_assertions"] + MANIFEST["hidden_assertions"]


def test_ci_check_all_pass_needs_every_manifest_assertion_to_pass(tmp_path):
    manifest = str(DIR / "manifest.json")
    good = _assertions_file(tmp_path, **{i: "pass" for i in ALL_IDS})
    assert _check("all-pass", good, manifest).returncode == 0
    for victim in ALL_IDS:                                                                # each one alone is enough to fail
        bad = _assertions_file(tmp_path, **{i: ("fail" if i == victim else "pass") for i in ALL_IDS})
        r = _check("all-pass", bad, manifest)
        assert r.returncode == 1 and victim in r.stdout, (victim, r.stdout)
    missing = _assertions_file(tmp_path, **{i: "pass" for i in ALL_IDS if i != "san_exact"})            # a hidden one absent
    r = _check("all-pass", missing, manifest)
    assert r.returncode == 1 and "san_exact" in r.stdout
    unknown = _assertions_file(tmp_path, **{i: ("unknown" if i == "ca_untouched" else "pass") for i in ALL_IDS})
    assert _check("all-pass", unknown, manifest).returncode == 1                        # unknown is not a pass


def test_ci_check_assertions_matches_each_expectation_exactly(tmp_path):
    f = _assertions_file(tmp_path, x509_not_expired="fail", ca_untouched="pass")
    assert _check("assertions", f, "x509_not_expired=fail", "ca_untouched=pass").returncode == 0
    for wrong in ("x509_not_expired=pass", "ca_untouched=fail", "san_exact=pass"):       # the last one is not in the file
        assert _check("assertions", f, wrong).returncode == 1, wrong
    assert _check("assertions", f, "x509_not_expired=maybe").returncode == 1


def test_ci_check_metrics_each_bound_is_enforced(tmp_path):
    good = {"availability": 0.9, "latency_p95_ms": 10.0, "mttr_s": 12.0, "blast_radius": 0, "restarts": 0, "downtime_s": 8.0}
    f = _write(tmp_path, "m.json", good)
    assert _check("metrics", f, "--recovered", "--blast-radius", "0", "--restarts", "0", "--max-availability", "0.999").returncode == 0
    cases = [({**good, "mttr_s": None}, ["--recovered"]), ({**good, "blast_radius": 1}, ["--blast-radius", "0"]),
             ({**good, "restarts": 1}, ["--restarts", "0"]), ({**good, "restarts": 0}, ["--min-restarts", "1"]),
             ({**good, "availability": 1.0}, ["--max-availability", "0.999"]), ({**good, "availability": 0.4}, ["--min-availability", "0.5"])]
    for metrics, flags in cases:
        r = _check("metrics", _write(tmp_path, "m2.json", metrics), *flags)
        assert r.returncode == 1 and "FAIL" in r.stdout, (flags, r.stdout)
    r = _check("metrics", _write(tmp_path, "m3.json", "UNKNOWN: nothing to measure"), "--recovered")
    assert r.returncode == 1 and "not JSON" in (r.stdout + r.stderr)


def test_ci_check_witness_compares_with_the_manifest_tolerance(tmp_path):
    tol = MANIFEST["independent_measurement"]["tolerance"]
    rm = {"availability": 0.90, "latency_p95_ms": 10.0, "mttr_s": 12.0, "downtime_s": 8.0}
    manifest = str(DIR / "manifest.json")

    def run(w):
        return _check("witness", _write(tmp_path, "r.json", rm), _write(tmp_path, "w.json", {"metrics": w}), manifest)

    assert run({**rm}).returncode == 0
    assert run({**rm, "availability": rm["availability"] - tol["availability"] + 0.001}).returncode == 0
    assert run({**rm, "availability": rm["availability"] - tol["availability"] - 0.01}).returncode == 1
    assert run({**rm, "mttr_s": rm["mttr_s"] + tol["mttr_s"] + 1}).returncode == 1
    assert run({**rm, "downtime_s": rm["downtime_s"] + tol["downtime_s"] + 1}).returncode == 1
    assert run({**rm, "latency_p95_ms": rm["latency_p95_ms"] * 4}).returncode == 1
    never = run({**rm, "mttr_s": None})                                                  # the witness never saw a recovery
    assert never.returncode == 1 and "did not measure" in never.stdout and "Traceback" not in never.stderr, (never.stdout, never.stderr)


def test_ci_check_annotates_only_inside_github_actions_and_escapes_the_message(tmp_path):
    f = _assertions_file(tmp_path, x509_not_expired="pass")
    quiet = _check("assertions", f, "x509_not_expired=fail", env={"GITHUB_ACTIONS": ""})
    assert quiet.returncode == 1 and "::error" not in quiet.stdout
    loud = _check("assertions", f, "x509_not_expired=fail", env={"GITHUB_ACTIONS": "true"})
    ann = [l for l in loud.stdout.splitlines() if l.startswith("::error title=cfr container check failed::")]
    assert len(ann) == 1 and "x509_not_expired" in ann[0], loud.stdout
    pct = _check("assertions", _write(tmp_path, "p.jsonl", '{"id": "a%b", "result": "pass"}\n'), "a%b=fail",
                 env={"GITHUB_ACTIONS": "true"})
    assert "%25" in pct.stdout.split("::error", 1)[1]                                     # a literal % is escaped
