#!/usr/bin/env python3
"""A standard-library target for zap: an API with an OpenAPI definition, and a
small site with a reflected XSS.

Binds 127.0.0.1 on an OS-assigned port and logs every request it receives as
one JSON line. It is also an HTTP upstream proxy: a request for any other host
(an absolute-form request line, or CONNECT) is logged and answered 502 without
resolving that host, so a tool told to use it as its proxy cannot reach
anything but this server, and every attempt to is counted. zap is pointed at
it with `-config network.connection.httpProxy.enabled=true`, `...host=127.0.0.1`
and `...port=<port>` (`proxy_flags`). As a proxy it also answers, as itself, for
the `aliases` it was started with: `zap-fixture.test:80` lets a scan name the
scheme's default port, with no privileged port bound and no name resolved.

The two definitions beside this file, `openapi.json` and `openapi-v1.json`,
are `write_specs`' output; `spec()` is what the server serves.

Modes
-----
``api``
    ``GET /api/items?q=&limit=``, ``GET /api/items/{id}``, ``POST /api/login``,
    ``GET /api/admin/users``. ``/`` links to nothing. ``/openapi.json`` serves
    the spec (``servers: [{url: http://prod.invalid/}]``) and
    ``/openapi-v1.json`` the variant whose server has the base path ``/v1``.
    The API also answers under one leading path segment (``/v1/api/items``),
    so a base path shows in the log rather than as a 404.
``spider``
    ``/`` links to ``/search?q=hello``, which reflects ``q`` into HTML
    unescaped (a reflected XSS). ``/app/`` links, relatively, to
    ``search?q=hello`` (``/app/search``), which does the same. ``/app``
    redirects 301 to ``/app/``, as a static server does for a directory.
    Routed on the percent-decoded path, as a server is: ``/my%20app/`` is
    the directory ``/my app/``, which links and reflects as ``/app/`` does.

Each log line: ``t``, ``via`` (``direct`` | ``proxy``), ``method``, ``host``
(the Host header), ``target`` (the host a proxied request named), ``path``,
``query``, ``body_len``, ``op`` (the route matched, ``offsite`` for another
host), ``prefix`` (a leading segment before ``/api``), ``payload`` (see
``looks_like_payload``), ``status``, ``ua``.

Entry points
------------
``python fixture_server.py --mode api --log requests.jsonl [--port-file F]``
    prints ``PORT <n>`` and serves until killed.
``start(mode, log_path, aliases=()) -> Fixture``
    for tests: ``.port``, ``.url``, ``.close()``.
``write_specs(directory)``
    writes ``openapi.json`` and ``openapi-v1.json``.
``read_log(path)``, ``proxy_flags(port)``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

SPEC_SERVER = "http://prod.invalid/"
SPEC_SERVER_V1 = "http://prod.invalid/v1"


def spec(server: str = SPEC_SERVER) -> dict:
    """An OpenAPI 3 definition of exactly the four operations."""
    json_body = {"application/json": {"schema": {"type": "object"}}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "fixture items API", "version": "1.0.0"},
        "servers": [{"url": server}],
        "paths": {
            "/api/items": {
                "get": {
                    "operationId": "listItems",
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer"},
                        },
                    ],
                    "responses": {
                        "200": {"description": "items", "content": json_body}
                    },
                }
            },
            "/api/items/{id}": {
                "get": {
                    "operationId": "getItem",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "one item", "content": json_body}
                    },
                }
            },
            "/api/login": {
                "post": {
                    "operationId": "login",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "401": {"description": "refused", "content": json_body}
                    },
                }
            },
            "/api/admin/users": {
                "get": {
                    "operationId": "listUsers",
                    "responses": {
                        "200": {"description": "users", "content": json_body}
                    },
                }
            },
        },
    }


def write_specs(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    root = directory / "openapi.json"
    v1 = directory / "openapi-v1.json"
    for path, server in ((root, SPEC_SERVER), (v1, SPEC_SERVER_V1)):
        path.write_bytes((json.dumps(spec(server), indent=2) + "\n").encode("utf-8"))
    return root, v1


# A value counts as a payload when it holds a character outside
# `[A-Za-z0-9 _.@-]` or one of these words. ZAP's import and spider send plain
# values (`10`, `John Doe`, `hello`); its active scan sends quotes, angle
# brackets, `../`, URLs, SQL and shell fragments.
_PLAIN = re.compile(r"^[A-Za-z0-9 _.@-]*$")
_WORDS = re.compile(
    r"script|alert|onerror|select|union|sleep|waitfor|passwd|system\.ini|win\.ini"
    r"|\band\b|\bor\b|https?:|file:|0w45pz4p",
    re.IGNORECASE,
)


def _values(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _values(v)
    elif obj is not None:
        yield str(obj)


def looks_like_payload(values) -> bool:
    return any(not _PLAIN.match(v) or _WORDS.search(v) for v in values if v)


_API = re.compile(
    r"^(?P<prefix>/[^/]+)?/api/(?:(?P<items>items)(?:/(?P<id>.*))?|(?P<login>login)"
    r"|(?P<admin>admin/users))$"
)

_INDEX_API = b"<html><body><h1>fixture API</h1><p>No links here.</p></body></html>"
_INDEX_SPIDER = (
    b'<html><body><h1>fixture site</h1><a href="/search?q=hello">search</a>'
    b"</body></html>"
)
_INDEX_APP = (
    b'<html><body><h1>fixture app</h1><a href="search?q=hello">search</a></body></html>'
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "fixture/1"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------
    def log_message(self, format, *args):
        pass

    def _own(self, netloc: str) -> bool:
        return netloc.lower() in self.server.own_netlocs  # type: ignore[attr-defined]

    def _record(self, **fields) -> None:
        fields.setdefault("t", round(time.time(), 3))
        fields.setdefault("ua", self.headers.get("User-Agent", "")[:120])
        fields.setdefault("host", self.headers.get("Host", ""))
        line = json.dumps(fields, sort_keys=True) + "\n"
        with self.server.log_lock:  # type: ignore[attr-defined]
            with open(self.server.log_path, "ab") as fh:  # type: ignore[attr-defined]
                fh.write(line.encode("utf-8"))

    def _send(self, status: int, body: bytes, ctype: str, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json")

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    # -- dispatch ---------------------------------------------------------
    def do_CONNECT(self):
        self._record(
            via="proxy",
            method="CONNECT",
            target=self.path,
            path="",
            query="",
            body_len=0,
            op="offsite",
            prefix="",
            payload=False,
            status=502,
        )
        self._send(502, b"fixture: no upstream\n", "text/plain")

    @staticmethod
    def _request_values(path: str, params, body: bytes) -> list[str]:
        """What a payload would be carried in: query names and values, body
        values (JSON or form), and the path past a route's fixed part (the
        `{id}` of `/api/items/{id}`)."""
        values = [v for _, v in params] + [k for k, _ in params]
        if body:
            text = body.decode("utf-8", "replace")
            try:
                values += list(_values(json.loads(text)))
            except ValueError:
                values += [v for _, v in parse_qsl(text, keep_blank_values=True)] or [
                    text
                ]
        m = _API.match(unquote_plus(path))
        if m and m.group("id") is not None:
            values.append(m.group("id"))
        return values

    def _dispatch(self):
        body = self._body()
        via = "direct"
        target = ""
        raw = self.path
        if "://" in raw.split("?", 1)[0]:
            parts = urlsplit(raw)
            via = "proxy"
            target = parts.netloc
            if not self._own(parts.netloc):
                params = parse_qsl(parts.query, keep_blank_values=True)
                m = _API.match(unquote_plus(parts.path))
                self._record(
                    via=via,
                    method=self.command,
                    target=target,
                    path=parts.path,
                    query=parts.query,
                    body_len=len(body),
                    op="offsite",
                    prefix=(m.group("prefix") or "") if m else "",
                    payload=looks_like_payload(
                        self._request_values(parts.path, params, body)
                    ),
                    status=502,
                )
                self._send(502, b"fixture: no upstream\n", "text/plain")
                return
            raw = parts.path + ("?" + parts.query if parts.query else "")
        parts = urlsplit(raw)
        path, query = parts.path, parts.query
        params = parse_qsl(query, keep_blank_values=True)
        status, op, prefix = self._route(path, dict(params), body)
        self._record(
            via=via,
            method=self.command,
            target=target,
            path=path,
            query=query,
            body_len=len(body),
            op=op,
            prefix=prefix,
            payload=looks_like_payload(self._request_values(path, params, body)),
            status=status,
        )

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _dispatch

    # -- routes -----------------------------------------------------------
    def _route(self, path: str, params: dict, body: bytes) -> tuple[int, str, str]:
        mode = self.server.mode  # type: ignore[attr-defined]
        if mode == "api":
            if path == "/":
                self._send(200, _INDEX_API, "text/html")
                return 200, "root", ""
            if path in ("/openapi.json", "/openapi-v1.json"):
                server = SPEC_SERVER if path == "/openapi.json" else SPEC_SERVER_V1
                self._send(200, json.dumps(spec(server)).encode(), "application/json")
                return 200, "spec", ""
            m = _API.match(unquote_plus(path))
            if not m:
                self._json(404, {"error": "not found"})
                return 404, "other", ""
            prefix = m.group("prefix") or ""
            if m.group("items") and m.group("id") is None:
                if self.command != "GET":
                    self._json(405, {"error": "method"})
                    return 405, "items_list", prefix
                q = params.get("q", "")
                self._json(200, {"q": q, "limit": params.get("limit", ""), "items": []})
                return 200, "items_list", prefix
            if m.group("items"):
                item = m.group("id")
                if self.command != "GET":
                    self._json(405, {"error": "method"})
                    return 405, "items_get", prefix
                if item.isdigit():
                    self._json(200, {"id": int(item), "name": "example"})
                    return 200, "items_get", prefix
                self._json(404, {"error": "no such item"})
                return 404, "items_get", prefix
            if m.group("login"):
                if self.command != "POST":
                    self._json(405, {"error": "method"})
                    return 405, "login", prefix
                self._json(401, {"error": "invalid credentials"})
                return 401, "login", prefix
            self._json(200, {"users": [{"name": "example"}]})
            return 200, "admin_users", prefix

        # spider
        path = unquote(path)
        if path == "/":
            self._send(200, _INDEX_SPIDER, "text/html")
            return 200, "root", ""
        if path == "/app":
            self._send(301, b"", "text/html", {"Location": "/app/"})
            return 301, "app_redirect", ""
        if path in ("/app/", "/my app/"):
            self._send(200, _INDEX_APP, "text/html")
            return 200, ("app_root" if path == "/app/" else "spaced_root"), ""
        searches = {
            "/search": "search",
            "/app/search": "app_search",
            "/my app/search": "spaced_search",
        }
        if path in searches:
            q = params.get("q", "")
            # Unescaped on purpose: the reflected XSS zap should find.
            page = f"<html><body><p>Results for: {q}</p></body></html>"
            self._send(200, page.encode("utf-8"), "text/html")
            return 200, searches[path], ""
        self._send(404, b"<html><body>not found</body></html>", "text/html")
        return 404, "other", ""


class Fixture:
    def __init__(
        self, mode: str, log_path: Path, aliases: tuple[str, ...] = ()
    ) -> None:
        if mode not in ("api", "spider"):
            raise ValueError(f"unknown mode {mode!r}")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.httpd.mode = mode  # type: ignore[attr-defined]
        self.httpd.log_path = Path(log_path)  # type: ignore[attr-defined]
        self.httpd.log_lock = threading.Lock()  # type: ignore[attr-defined]
        self.httpd.own_netlocs = {  # type: ignore[attr-defined]
            f"127.0.0.1:{self.port}",
            f"localhost:{self.port}",
            *(alias.lower() for alias in aliases),
        }
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> Fixture:
        self._thread.start()
        return self

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def start(mode: str, log_path: Path, aliases: tuple[str, ...] = ()) -> Fixture:
    return Fixture(mode, log_path, aliases).start()


def read_log(log_path: Path) -> list[dict]:
    if not Path(log_path).exists():
        return []
    return [
        json.loads(x) for x in Path(log_path).read_bytes().decode().splitlines() if x
    ]


def proxy_flags(port: int) -> list[str]:
    """zap's `-config` keys that send every request through this server
    (ZAP 2.17, network add-on 0.25.0)."""
    return [
        "-config",
        "network.connection.httpProxy.enabled=true",
        "-config",
        "network.connection.httpProxy.host=127.0.0.1",
        "-config",
        f"network.connection.httpProxy.port={port}",
    ]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", choices=("api", "spider"), default="api")
    ap.add_argument("--log", required=True, type=Path)
    ap.add_argument("--port-file", type=Path)
    ap.add_argument("--spec-dir", type=Path, help="also write the two specs here")
    args = ap.parse_args(argv)
    if args.spec_dir:
        write_specs(args.spec_dir)
    fx = Fixture(args.mode, args.log)
    if args.port_file:
        args.port_file.write_bytes(str(fx.port).encode())
    print(f"PORT {fx.port}", flush=True)
    try:
        fx.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        fx.httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
