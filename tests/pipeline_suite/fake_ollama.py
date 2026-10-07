"""TEST DOUBLE of the Ollama HTTP API (version/tags/chat).

It declares itself through /api/version ("...-test-double") so the pipeline labels every
run against it as TEST_DOUBLE and the Gate rejects it unless policy.allow_test_double is set.
It exists only to exercise protocol + gate logic where no live Ollama is reachable.
Real-runtime evidence comes exclusively from tests/test_real_ollama.py.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ola_pipeline.verify import CANARY_TASK


class FakeOllama:
    def __init__(self):
        self.models = {}      # name -> digest | None
        self.scripts = {}     # model -> [str | callable(idx, messages) -> str]
        self.delays = {}      # model -> seconds
        self.http_fail = {}   # model -> status code
        self.calls = {}       # model -> count
        self.requests = []    # (method, path, model|None)
        self.messages = {}    # model -> [messages per call]
        self.version = "0.0.0-test-double"
        self.bodies = []
        self.canary_mode = "reject"   # reject | accept | invalid | fail  (how the judge treats 2+2=5)
        self.canary_calls = 0
        self._srv = None

    def add_model(self, name, digest="e5f6a1b2c3d4" * 5 + "abcd"):
        self.models[name] = digest

    def script(self, model, *responses):
        self.scripts[model] = list(responses)

    @property
    def url(self):
        return f"http://127.0.0.1:{self._srv.server_address[1]}"

    def start(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                outer.requests.append(("GET", self.path, None))
                if self.path == "/api/version":
                    return self._send(200, {"version": outer.version})
                if self.path == "/api/tags":
                    ms = []
                    for n, d in outer.models.items():
                        m = {"name": n, "model": n}
                        if d:
                            m["digest"] = d
                        ms.append(m)
                    return self._send(200, {"models": ms})
                self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model = body.get("model")
                outer.requests.append(("POST", self.path, model))
                outer.bodies.append(body)
                if self.path != "/api/chat" or model not in outer.models:
                    return self._send(404, {"error": "model not found"})
                if CANARY_TASK in json.dumps(body["messages"], ensure_ascii=False):
                    # calibration canary: answered by mode, never consumes the per-model script
                    outer.canary_calls += 1
                    mode = outer.canary_mode
                    if mode == "fail":
                        return self._send(500, {"error": "boom"})
                    txt = {"reject": json.dumps({"decision": "BLOCK", "quality_score": 5, "findings": ["2 + 2 is 4, not 5"],
                                                 "required_corrections": ["answer 4"], "reason": "wrong"}),
                           "accept": json.dumps({"decision": "PASS", "quality_score": 100, "findings": [],
                                                 "required_corrections": [], "reason": "fully satisfies the task"}),
                           "invalid": "definitely not json"}[mode]
                    return self._send(200, {"model": model, "created_at": "2026-10-03T00:00:00Z",
                                            "message": {"role": "assistant", "content": txt},
                                            "done": True, "done_reason": "stop", "total_duration": 1000,
                                            "eval_count": 5, "prompt_eval_count": 7})
                idx = outer.calls.get(model, 0)
                outer.calls[model] = idx + 1
                outer.messages.setdefault(model, []).append(body["messages"])
                if outer.delays.get(model):
                    time.sleep(outer.delays[model])
                if outer.http_fail.get(model):
                    return self._send(outer.http_fail[model], {"error": "boom"})
                items = outer.scripts.get(model, ["default answer"])
                item = items[min(idx, len(items) - 1)]
                text = item(idx, body["messages"]) if callable(item) else item
                # a dict item is a whole message (e.g. {"content": ..., "thinking": ...} of a reasoning model)
                message = {"role": "assistant", **text} if isinstance(text, dict) else {"role": "assistant", "content": text}
                self._send(200, {
                    "model": model, "created_at": "2026-10-03T00:00:00Z",
                    "message": message,
                    "done": True, "done_reason": "stop", "total_duration": 1000,
                    "eval_count": 5, "prompt_eval_count": 7,
                })

        class S(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        self._srv = S(("127.0.0.1", 0), H)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
