"""A very small HTTP server with a routing table and a websocket endpoint.

Built on :mod:`http.server` so the controller needs no framework.  Handlers
receive a :class:`Request` and return a :class:`Response`.

Static files are resolved against a single root.  Both ``/style.css`` and
``/static/style.css`` work, so the markup can use whichever it likes.
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from . import ws

#: Explicit content types.  ``mimetypes`` consults the Windows registry, which
#: frequently reports ``text/plain`` for ``.js`` and ``.css``; browsers then
#: either refuse to run the script or ignore the stylesheet entirely.
CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
    ".zip": "application/zip",
}

#: Prefix stripped from request paths before resolving against the static root.
STATIC_PREFIX = "static/"


class Request:
    """An incoming HTTP request."""

    def __init__(self, method: str, path: str, query: dict[str, list[str]],
                 headers: Any, body: bytes) -> None:
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.path_params: dict[str, str] = {}

    def param(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[0] if values else default

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        return json.loads(self.body.decode("utf-8"))


class Response:
    """An outgoing HTTP response."""

    def __init__(self, status: int = 200, body: bytes = b"",
                 content_type: str = "text/plain; charset=utf-8") -> None:
        self.status = status
        self.body = body
        self.headers: dict[str, str] = {
            "Content-Type": content_type,
            "X-Content-Type-Options": "nosniff",
        }

    @classmethod
    def json(cls, status: int, payload: Any) -> "Response":
        return cls(status, json.dumps(payload).encode("utf-8"),
                   "application/json; charset=utf-8")

    @classmethod
    def text(cls, status: int, text: str) -> "Response":
        return cls(status, text.encode("utf-8"))

    @classmethod
    def no_content(cls) -> "Response":
        return cls(204, b"", "text/plain; charset=utf-8")

    @classmethod
    def file(cls, path: str) -> "Response":
        """Read a file from disk and guess its type from the extension."""
        with open(path, "rb") as handle:
            data = handle.read()
        extension = os.path.splitext(path)[1].lower()
        content_type = (
            CONTENT_TYPES.get(extension)
            or mimetypes.guess_type(path)[0]
            or "application/octet-stream"
        )
        response = cls(200, data, content_type)
        response.headers["Cache-Control"] = "no-store"
        return response


class Application:
    """Routing table plus websocket hook."""

    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern[str], Callable[[Request], Response]]] = []
        self._socket_handler: Optional[Callable[[ws.WebSocket, Request], None]] = None
        self._static_root: Optional[str] = None

    # -- registration ----------------------------------------------------

    def route(self, method: str, pattern: str):
        """Register a handler.  ``pattern`` may contain ``{name}`` segments."""
        compiled = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")

        def decorator(handler: Callable[[Request], Response]) -> Callable[[Request], Response]:
            self._routes.append((method.upper(), compiled, handler))
            return handler

        return decorator

    def on_socket(self, handler: Callable[[ws.WebSocket, Request], None]) -> None:
        """Register the websocket handler."""
        self._socket_handler = handler

    def static(self, root: str) -> None:
        """Serve files from ``root`` for any unmatched GET."""
        self._static_root = os.path.abspath(root)

    # -- dispatch --------------------------------------------------------

    def dispatch(self, request: Request) -> Response:
        for method, pattern, handler in self._routes:
            if method != request.method:
                continue
            match = pattern.match(request.path)
            if match:
                request.path_params = match.groupdict()
                return handler(request)

        if request.method in ("GET", "HEAD") and self._static_root:
            return self._serve_static(request)
        return Response.json(404, {"error": "not found"})

    def _serve_static(self, request: Request) -> Response:
        """Resolve a URL path against the static root, safely."""
        assert self._static_root is not None
        root = self._static_root

        relative = request.path.lstrip("/") or "index.html"
        # The markup asks for /static/style.css but the root already *is*
        # the static folder, so drop the prefix if it is there.
        if relative.startswith(STATIC_PREFIX):
            relative = relative[len(STATIC_PREFIX):]
        if not relative or relative == ".":
            relative = "index.html"

        candidate = os.path.abspath(os.path.join(root, relative))

        # Guard against traversal (..\..\something).
        if candidate != root and not candidate.startswith(root + os.sep):
            return Response.json(403, {"error": "forbidden"})

        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.html")

        if not os.path.isfile(candidate):
            return Response.json(404, {"error": "not found", "path": relative})

        try:
            return Response.file(candidate)
        except OSError as error:
            return Response.json(500, {"error": str(error)})


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SysPy"

    def log_message(self, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:      # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:     # noqa: N802
        self._dispatch("HEAD")

    def do_POST(self) -> None:     # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:   # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)

        if path == "/ws" and method == "GET":
            self._upgrade(parsed)
            return

        if path == "/favicon.ico":
            self._write(Response.no_content())
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        request = Request(method, path, parse_qs(parsed.query), self.headers, body)

        try:
            response = self.server.app.dispatch(request)  # type: ignore[attr-defined]
        except Exception:
            response = Response.json(500, {"error": traceback.format_exc()})

        self._write(response, include_body=method != "HEAD")

    def _write(self, response: Response, include_body: bool = True) -> None:
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if include_body and response.body:
            self.wfile.write(response.body)

    def _upgrade(self, parsed: Any) -> None:
        client_key = self.headers.get("Sec-WebSocket-Key")
        if not client_key:
            self._write(Response.text(400, "missing Sec-WebSocket-Key"))
            return

        token = ws.accept_token(client_key)
        self.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + token.encode("ascii") + b"\r\n\r\n"
        )
        self.wfile.flush()
        self.close_connection = True

        handler = self.server.app._socket_handler  # type: ignore[attr-defined]
        if handler is None:
            return
        try:
            import socket as _sock
            self.connection.setsockopt(_sock.SOL_SOCKET, _sock.SO_KEEPALIVE, 1)
        except Exception:
            pass
        socket = ws.WebSocket(self.rfile, self.wfile)
        request = Request("GET", parsed.path, parse_qs(parsed.query), self.headers, b"")
        handler(socket, request)


class Server(ThreadingHTTPServer):
    """Threaded HTTP server carrying an :class:`Application`."""

    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def __init__(self, address: tuple[str, int], app: Application) -> None:
        super().__init__(address, _Handler)
        self.app = app

    def server_bind(self) -> None:
        if os.name == "nt":
            import socket
            self.socket.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", 1), 1)
        super().server_bind()
