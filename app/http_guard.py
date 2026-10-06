"""Request-size limit and security headers (pure ASGI, no dependency).

The limit is applied BEFORE the body is parsed and before authentication: an unauthenticated 50 MB POST used to be read
and parsed in full (about 150 MB of RAM per request). Content-Length is checked first (every Content-Length header, not
only the last); a body without it (chunked) is counted while it streams. The moment the budget is exceeded the
application is told the client went away (`http.disconnect`), so it can never act on a truncated prefix of the body,
whatever that prefix looks like (a complete JSON object followed by padding used to be executed and answered 413).
Whatever the application then raises or answers is discarded and the caller gets 413.

Paths are matched the way the router matches them: `scope["root_path"]` (uvicorn --root-path puts it in front of
`scope["path"]`) is stripped first, so the smaller /stripe/webhook budget also holds behind a path prefix.
"""
import json
import os
import re

DEFAULT_MAX_BODY_BYTES = 1_048_576          # 1 MiB for every JSON route
WEBHOOK_MAX_BODY_BYTES = 65_536             # Stripe events are a few KB
_WEBHOOK_PATHS = {"/stripe/webhook"}
_PRODUCT_PAGE = "/"                         # the only route that gets the CSP (it is the only page the product serves)

_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
]
_CONTENT_LENGTH = re.compile(rb"\s*[0-9]{1,18}\s*")


def security_headers() -> dict:
    """The same headers as a dict, for responses that are built outside the guard (the 500 handler)."""
    return {k.decode("ascii"): v.decode("ascii") for k, v in _SECURITY_HEADERS}


def route_path(scope) -> str:
    """The path the router sees: scope['path'] without scope['root_path'] (same rule as starlette's get_route_path)."""
    path = scope.get("path", "") or ""
    root = (scope.get("root_path", "") or "").rstrip("/")
    if root and path.startswith(root) and (len(path) == len(root) or path[len(root)] == "/"):
        path = path[len(root):]
    return path or "/"


def max_body_bytes(path: str) -> int:
    if (path.rstrip("/") or "/") in _WEBHOOK_PATHS:
        return WEBHOOK_MAX_BODY_BYTES
    try:
        value = int(os.environ.get("OLA_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES))
        return value if value > 0 else DEFAULT_MAX_BODY_BYTES
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES


def _declared_too_big(headers, limit: int) -> bool:
    """True when ANY Content-Length header is not a plain non-negative integer or is over the limit."""
    for name, value in headers:
        if name.lower() != b"content-length":
            continue
        if not _CONTENT_LENGTH.fullmatch(value) or int(value) > limit:
            return True
    return False


class HttpGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        route = route_path(scope)
        limit = max_body_bytes(route)
        if _declared_too_big(scope.get("headers") or [], limit):
            await self._reject(send, limit)
            return
        is_page = route == _PRODUCT_PAGE

        state = {"seen": 0, "over": False, "started": False}

        async def counting_receive():
            if state["over"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body") or b"")
                if state["seen"] > limit:
                    state["over"] = True
                    # not an empty "final" chunk: that would let the application run on the prefix it already got
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            if state["over"] and not state["started"]:
                return                                   # the app's answer to an aborted request is replaced by the 413
            if message["type"] == "http.response.start":
                state["started"] = True
                headers = list(message.get("headers") or [])
                present = {k.lower() for k, _ in headers}
                extra = list(_SECURITY_HEADERS)
                if is_page and any(k.lower() == b"content-type" and v.lower().startswith(b"text/html")
                                   for k, v in headers):
                    extra.append((b"content-security-policy", _CSP.encode()))
                message = dict(message, headers=headers + [(k, v) for k, v in extra if k not in present])
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            if not state["over"] or state["started"]:
                raise
            # the application failed because we told it the client was gone; the answer is the 413 below
        if state["over"] and not state["started"]:
            await self._reject(send, limit)

    @staticmethod
    async def _reject(send, limit):
        body = json.dumps({"detail": f"request body too large (limit {limit} bytes)"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close"), *_SECURITY_HEADERS]})
        await send({"type": "http.response.body", "body": body})
