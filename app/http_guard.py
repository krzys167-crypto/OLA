"""Request-size limit and security headers (pure ASGI, no dependency).

The limit is applied BEFORE the body is parsed and before authentication: an unauthenticated 50 MB POST used to be read
and parsed in full (about 150 MB of RAM per request). Content-Length is checked first; a body without it (chunked) is
counted while it streams and the request is answered 413 as soon as the budget is exceeded.
"""
import json
import os

DEFAULT_MAX_BODY_BYTES = 1_048_576          # 1 MiB for every JSON route
WEBHOOK_MAX_BODY_BYTES = 65_536             # Stripe events are a few KB
_WEBHOOK_PATHS = {"/stripe/webhook"}

_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
]


def max_body_bytes(path: str) -> int:
    if path in _WEBHOOK_PATHS:
        return WEBHOOK_MAX_BODY_BYTES
    try:
        value = int(os.environ.get("OLA_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES))
        return value if value > 0 else DEFAULT_MAX_BODY_BYTES
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES


class HttpGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = max_body_bytes(path)
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await self._reject(send, limit)
                return

        state = {"seen": 0, "over": False, "started": False}

        async def counting_receive():
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body", b""))
                if state["seen"] > limit:
                    state["over"] = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message):
            if state["over"]:
                return                                   # the app's answer to a truncated body is dropped
            if message["type"] == "http.response.start":
                state["started"] = True
                extra = list(_SECURITY_HEADERS)
                content_type = dict(message.get("headers") or []).get(b"content-type", b"")
                if content_type.startswith(b"text/html"):
                    extra.append((b"content-security-policy", _CSP.encode()))
                present = {k.lower() for k, _ in message.get("headers", [])}
                message = dict(message, headers=list(message.get("headers", [])) +
                               [(k, v) for k, v in extra if k not in present])
            await send(message)

        await self.app(scope, counting_receive, guarded_send)
        if state["over"] and not state["started"]:
            await self._reject(send, limit)

    @staticmethod
    async def _reject(send, limit):
        body = json.dumps({"detail": f"request body too large (limit {limit} bytes)"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                *_SECURITY_HEADERS]})
        await send({"type": "http.response.body", "body": body})
