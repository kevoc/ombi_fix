#!/usr/bin/env python3
"""
OmbiFix - a thin Jellyfin 10.11.x -> 12.x compatibility shim for Ombi 4.53.x.

Point Ombi's Jellyfin server settings at this proxy instead of at Jellyfin.
The proxy speaks the Jellyfin 10.11.11 API that Ombi expects and forwards
each request to a real Jellyfin 12 server.

WHY THIS IS NEEDED
------------------
Jellyfin 12 ships a migration (Jellyfin.Server/Migrations/Routines/
20260531160000_DisableLegacyAuthorization.cs) that forces
`EnableLegacyAuthorization = false`. With that off, Jellyfin's
AuthorizationContext ignores:
  * the `X-Emby-Authorization` header          (Ombi sends this on login)
  * the `X-Emby-Token` / `X-MediaBrowser-Token` headers (Ombi sends its API key this way)
  * the `api_key` query parameter
  * the `Emby` auth scheme name
Only `Authorization: MediaBrowser Token="...", Client="...", ...` and the
`ApiKey` query parameter are accepted.

Effect on Ombi:
  * Adding a new server fails: GET /Users with X-MediaBrowser-Token -> 401.
  * Login fails: POST /Users/AuthenticateByName without a parsed Authorization
    header has no Client/DeviceId -> 400 "Error processing request."
  * Content/user sync jobs also get 401.
Routes and response JSON for the endpoints Ombi uses are otherwise unchanged
between 10.11.11 and 12.4, so bodies are passed through untouched.

ENDPOINTS OMBI CALLS (Ombi-4.53.10/src/Ombi.Api.External/MediaServers/Jellyfin/JellyfinApi.cs)
  GET  System/Info/Public                 GetPublicInformation (server setup "load info")
  GET  System/Info                        GetSystemInformation (health check)
  GET  users                              GetUsers (server setup test, user importer, landing page)
  POST users/authenticatebyname           LogIn (Ombi user login)
  GET  library/virtualfolders             GetLibraries (server setup "load libraries")
  GET  users/{userId}/items               GetAllMovies/Shows/Episodes, GetCollection (content sync)
  GET  users/{userId}/items/{itemId}      Get{Movie,Series,Episode}Information (metadata refresh)
Anything else returns 404 and is logged with an "UNHANDLED" marker so a
future maintainer can see exactly what to add to ROUTES below.

USAGE
  python3 ombi_fix.py --upstream https://jellyfin.example.com [--port 8097]

Then in Ombi -> Settings -> Jellyfin set Hostname/Port to this proxy
(SSL off unless you terminate TLS in front of it) and set Ombi's API key to the
Ombi's Jellyfin API key (created in Jellyfin Dashboard -> API Keys).

Configuration (CLI flag or environment variable):
  --upstream / OMBIFIX_UPSTREAM        Jellyfin 12 base URL (may include a path, e.g. https://host/jellyfin)
  --host / OMBIFIX_HOST                listen address (default 0.0.0.0)
  --port / OMBIFIX_PORT                listen port (default 8097)
  --base-path / OMBIFIX_BASE_PATH      path prefix Ombi uses (Ombi "Base URL"/SubDir), stripped before routing
  --insecure / OMBIFIX_INSECURE=1      skip TLS verification for upstream
  --timeout / OMBIFIX_TIMEOUT          upstream timeout seconds (default 300)
  --log-body-max / OMBIFIX_LOG_BODY_MAX  max chars of each body to log (default 4000, 0 = unlimited)
  --log-secrets / OMBIFIX_LOG_SECRETS=1  log tokens and passwords unredacted (debug only)
AUTH HANDLING
  The proxy stores no credentials. Ombi's own API key is read from
  X-MediaBrowser-Token / X-Emby-Token / X-Emby-Authorization / api_key and
  re-sent as `Authorization: MediaBrowser Token="<Ombi's key>"` (plus Ombi's
  Client/Device fields), so Jellyfin itself decides whether the key is valid.
  System/Info/Public and Users/AuthenticateByName are sent with no token
  (anonymous in Jellyfin). Other routes with no key are rejected with 401
  without contacting Jellyfin.

Only the Python 3.8+ standard library is required.
"""

import argparse
import itertools
import json
import logging
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("ombifix")

# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
# (method, regex matched case-insensitively against the path with base path
# stripped, name). Jellyfin routing is case-insensitive and Ombi sends mixed
# case ("users", "System/Info"), so match the same way.
# To support a new Ombi call: add a line here; it is forwarded with auth
# translated. If its request/response shape changed in Jellyfin 12, add a
# transform in REQUEST_TRANSFORMS / RESPONSE_TRANSFORMS keyed by name.
_ID = r"[0-9a-fA-F-]{32,36}"
ROUTES = [
    ("GET", r"/System/Info/Public", "public_info"),
    ("GET", r"/System/Info", "system_info"),
    ("GET", r"/Users", "users"),
    ("POST", r"/Users/AuthenticateByName", "authenticate_by_name"),
    ("GET", r"/Library/VirtualFolders", "virtual_folders"),
    ("GET", rf"/Users/{_ID}/Items", "user_items"),
    ("GET", rf"/Users/{_ID}/Items/{_ID}", "user_item"),
]
_COMPILED_ROUTES = [(m, re.compile(rf"^{p}/?$", re.IGNORECASE), n) for m, p, n in ROUTES]

# Request headers copied from Ombi to Jellyfin. Auth headers are rebuilt
# separately; Accept-Encoding is dropped so upstream bodies stay plain text
# (loggable, and Ombi does not need compression from a local proxy).
FORWARD_REQUEST_HEADERS = {"accept", "content-type", "user-agent", "accept-language"}
# Response headers copied from Jellyfin back to Ombi.
FORWARD_RESPONSE_HEADERS = {"content-type", "cache-control", "etag", "last-modified", "expires"}

# Client fields Jellyfin requires to create a session on AuthenticateByName.
# Ombi normally supplies these in X-Emby-Authorization; these fill any gaps.
DEFAULT_CLIENT_FIELDS = {"Client": "Ombi", "Device": "Ombi", "DeviceId": "v3", "Version": "v3"}

LEGACY_TOKEN_HEADERS = ("X-Emby-Token", "X-MediaBrowser-Token")
# Query keys carrying a token; consumed here and replaced by the Authorization header.
TOKEN_QUERY_KEYS = ("api_key", "apikey")

# Routes Jellyfin serves anonymously; no token is sent upstream for these.
# (Login must be anonymous: it creates a session for the user being checked.)
ANONYMOUS_ROUTES = {"public_info", "authenticate_by_name"}
PASSWORD_JSON_KEYS = {"pw", "password"}
TOKEN_JSON_KEYS = {"accesstoken", "token"}


class Config:
    upstream = ""
    base_path = ""
    insecure = False
    timeout = 300.0
    log_body_max = 4000
    log_secrets = False


CFG = Config()
_request_ids = itertools.count(1)


# --------------------------------------------------------------------------
# Redaction / logging helpers
# --------------------------------------------------------------------------
def redact(value):
    if CFG.log_secrets or not value:
        return value
    return value[:4] + "…(redacted)" if len(value) > 8 else "(redacted)"


def redact_auth_header(value):
    """Redact Token="..." inside a MediaBrowser/Emby authorization header."""
    if CFG.log_secrets:
        return value
    return re.sub(r'(Token\s*=\s*")([^"]*)(")', lambda m: m.group(1) + redact(m.group(2)) + m.group(3), value,
                  flags=re.IGNORECASE)


def redact_headers(headers):
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in ("authorization", "x-emby-authorization"):
            out[k] = redact_auth_header(v)
        elif lk in ("x-emby-token", "x-mediabrowser-token"):
            out[k] = redact(v)
        else:
            out[k] = v
    return out


def redact_query(query):
    if CFG.log_secrets:
        return query
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    return urllib.parse.urlencode(
        [(k, redact(v) if k.lower() in ("api_key", "apikey") else v) for k, v in pairs], safe=",")


def _redact_json(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in PASSWORD_JSON_KEYS
                    else redact(v) if isinstance(v, str) and k.lower() in TOKEN_JSON_KEYS
                    else _redact_json(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json(v) for v in obj]
    return obj


def body_for_log(body, content_type=""):
    if not body:
        return "<empty>"
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(body)} bytes binary>"
    if not CFG.log_secrets and ("json" in (content_type or "").lower() or text[:1] in "{["):
        try:
            text = json.dumps(_redact_json(json.loads(text)), ensure_ascii=False)
        except ValueError:
            pass
    if CFG.log_body_max and len(text) > CFG.log_body_max:
        return f"{text[:CFG.log_body_max]}…<truncated, {len(text)} chars total>"
    return text


# --------------------------------------------------------------------------
# Auth translation
# --------------------------------------------------------------------------
def parse_auth_header(value):
    """Parse 'MediaBrowser Client="Ombi", Token="x"' (or 'Emby ...') into
    (scheme, {field: value}). Mirrors Jellyfin's AuthorizationContext.GetParts."""
    value = (value or "").strip()
    if " " not in value:
        return None, {}
    scheme, rest = value.split(" ", 1)
    fields = {}
    for m in re.finditer(r'\s*([^=,\s]+)\s*=\s*(?:"([^"]*)"|([^,]*))\s*,?', rest):
        fields[m.group(1)] = urllib.parse.unquote(m.group(2) if m.group(2) is not None else m.group(3).strip())
    return scheme, fields


def build_auth_header(fields):
    order = ["Client", "Device", "DeviceId", "Version", "Token"]
    keys = [k for k in order if k in fields] + [k for k in fields if k not in order]
    return "MediaBrowser " + ", ".join(f'{k}="{urllib.parse.quote(fields[k], safe=" ._-:/")}"' for k in keys)


def translate_auth(headers, query_pairs, route_name):
    """Return (authorization_header_or_None, query_pairs_without_token_keys, notes, reject_reason_or_None).

    Ombi's token is collected from every legacy location and passed through
    unchanged in a modern `Authorization: MediaBrowser Token=...` header;
    Jellyfin validates it."""
    notes = []
    fields = {}

    # Modern header first (same precedence as Jellyfin), then legacy.
    for hname in ("Authorization", "X-Emby-Authorization"):
        raw = headers.get(hname)
        if not raw:
            continue
        scheme, parsed = parse_auth_header(raw)
        if scheme and scheme.lower() in ("mediabrowser", "emby"):
            for k, v in parsed.items():
                fields.setdefault(k, v)
            if hname != "Authorization" or scheme.lower() != "mediabrowser":
                notes.append(f"converted {hname} (scheme {scheme}) -> Authorization: MediaBrowser")
        else:
            notes.append(f"ignored {hname} with unsupported scheme {scheme!r}")

    if not fields.get("Token"):
        for hname in LEGACY_TOKEN_HEADERS:
            if headers.get(hname):
                fields["Token"] = headers[hname]
                notes.append(f"read Ombi token from legacy header {hname}")
                break

    kept = []
    for k, v in query_pairs:
        if k.lower() in TOKEN_QUERY_KEYS:
            if not fields.get("Token"):
                fields["Token"] = v
                notes.append(f"read Ombi token from query {k}")
            notes.append(f"removed query {k} from upstream URL")
            continue
        kept.append((k, v))

    client_token = fields.pop("Token", None)

    if route_name in ANONYMOUS_ROUTES:
        if client_token:
            notes.append("anonymous route: dropped Ombi's token, no API key sent upstream")
    else:
        if not client_token:
            return None, kept, notes, "Ombi sent no API key (check the API key in Ombi's Jellyfin settings)"
        fields["Token"] = client_token
        notes.append(f"forwarding Ombi's API key {redact(client_token)!r} for Jellyfin to validate")

    if route_name == "authenticate_by_name":
        for k, v in DEFAULT_CLIENT_FIELDS.items():
            if not fields.get(k):
                fields[k] = v
                notes.append(f"filled missing client field {k}={v!r} (required by Jellyfin 12 to create a session)")

    if not fields:
        return None, kept, notes, None
    return build_auth_header(fields), kept, notes, None


# Hooks for endpoints whose shape changes in future Jellyfin versions.
# Signature: fn(body_bytes, rid) -> body_bytes
REQUEST_TRANSFORMS = {}
RESPONSE_TRANSFORMS = {}


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "OmbiFix/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence default stderr access log; we log ourselves
        pass

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, status, body, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        rid = f"req-{next(_request_ids):05d}"
        started = time.monotonic()
        body = self._read_body()
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        log.info("[%s] <-- IN  %s %s?%s from %s", rid, self.command, parsed.path, redact_query(parsed.query),
                 self.client_address[0])
        log.info("[%s]     IN  headers: %s", rid, json.dumps(redact_headers(dict(self.headers.items()))))
        if body:
            log.info("[%s]     IN  body: %s", rid, body_for_log(body, self.headers.get("Content-Type", "")))

        route_path = path
        if CFG.base_path:
            if route_path.lower().startswith(CFG.base_path.lower()):
                route_path = route_path[len(CFG.base_path):] or "/"
            else:
                log.warning("[%s]     path %r does not start with configured base path %r", rid, path,
                            CFG.base_path)
        route_path = "/" + route_path.lstrip("/")

        route_name = None
        for method, rx, name in _COMPILED_ROUTES:
            if method == self.command and rx.match(route_path):
                route_name = name
                break

        if route_name is None:
            msg = {"error": "Not implemented by OmbiFix", "method": self.command, "path": route_path}
            log.warning("[%s] UNHANDLED %s %s (query: %s) -> 404. If Ombi needs this, add it to ROUTES in %s",
                        rid, self.command, route_path, redact_query(parsed.query), os.path.basename(__file__))
            self._send(404, json.dumps(msg).encode(), {"Content-Type": "application/json"})
            log.info("[%s] --> OUT 404 (%.0f ms)", rid, (time.monotonic() - started) * 1000)
            return

        log.info("[%s]     matched route %r", rid, route_name)
        auth, query_pairs, notes, reject = translate_auth(self.headers, query_pairs, route_name)
        for n in notes:
            log.info("[%s]     auth: %s", rid, n)
        if reject:
            log.warning("[%s]     REJECTED %s %s -> 401: %s", rid, self.command, route_path, reject)
            self._send(401, json.dumps({"error": reject}).encode(), {"Content-Type": "application/json"})
            log.info("[%s] --> OUT 401 (%.0f ms)", rid, (time.monotonic() - started) * 1000)
            return

        if route_name in REQUEST_TRANSFORMS and body:
            body = REQUEST_TRANSFORMS[route_name](body, rid)
            log.info("[%s]     transformed request body: %s", rid, body_for_log(body, "application/json"))

        out_headers = {k: v for k, v in self.headers.items() if k.lower() in FORWARD_REQUEST_HEADERS}
        if auth:
            out_headers["Authorization"] = auth
        # Ombi's own client IP, so Jellyfin's activity log / lockout logic sees something meaningful.
        out_headers["X-Forwarded-For"] = self.client_address[0]

        query = urllib.parse.urlencode(query_pairs, safe=",")
        url = CFG.upstream + route_path + (f"?{query}" if query else "")
        self._forward(rid, started, route_name, url, out_headers, body)

    def _forward(self, rid, started, route_name, url, out_headers, body):
        log.info("[%s] ==> UP  %s %s", rid, self.command, redact_query_url(url))
        log.info("[%s]     UP  headers: %s", rid, json.dumps(redact_headers(out_headers)))
        if body:
            log.info("[%s]     UP  body: %s", rid, body_for_log(body, out_headers.get("Content-Type", "")))

        req = urllib.request.Request(url, data=body if self.command in ("POST", "PUT", "PATCH") else None,
                                     headers=out_headers, method=self.command)
        ctx = ssl._create_unverified_context() if CFG.insecure else None
        try:
            try:
                resp = urllib.request.urlopen(req, timeout=CFG.timeout, context=ctx)
            except urllib.error.HTTPError as e:
                resp = e  # non-2xx: still pass status and body through to Ombi
            status = resp.status if hasattr(resp, "status") else resp.code
            resp_body = resp.read()
            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() in FORWARD_RESPONSE_HEADERS}
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            reason = getattr(e, "reason", e)
            log.error("[%s] <== UP  FAILED to reach Jellyfin: %s", rid, reason)
            msg = json.dumps({"error": "OmbiFix could not reach upstream Jellyfin", "detail": str(reason)}).encode()
            self._send(502, msg, {"Content-Type": "application/json"})
            log.info("[%s] --> OUT 502 (%.0f ms)", rid, (time.monotonic() - started) * 1000)
            return

        ctype = resp_headers.get("Content-Type", "")
        log.info("[%s] <== UP  %s (%d bytes, %s)", rid, status, len(resp_body), ctype or "no content-type")
        log.info("[%s]     UP  response body: %s", rid, body_for_log(resp_body, ctype))
        if status >= 400:
            log.warning("[%s]     upstream returned %s for route %r - Ombi will treat this as a failure", rid,
                        status, route_name)
            if status == 401 and route_name == "authenticate_by_name":
                log.warning("[%s]     401 on login = wrong username/password (or user disabled) in Jellyfin", rid)
            elif status == 401:
                log.warning("[%s]     401 from Jellyfin means the API key set in Ombi is wrong or was revoked "
                            "in Jellyfin (Dashboard -> API Keys)", rid)
            elif status == 403:
                log.warning("[%s]     403 means the API key/user lacks permission (this endpoint may need an "
                            "admin or a Jellyfin API key)", rid)

        if route_name in RESPONSE_TRANSFORMS and 200 <= status < 300:
            resp_body = RESPONSE_TRANSFORMS[route_name](resp_body, rid)
            log.info("[%s]     transformed response body: %s", rid, body_for_log(resp_body, ctype))

        self._send(status, resp_body, resp_headers)
        log.info("[%s] --> OUT %s (%d bytes, %.0f ms)", rid, status, len(resp_body),
                 (time.monotonic() - started) * 1000)


def redact_query_url(url):
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(parts._replace(query=redact_query(parts.query)))


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
def probe_upstream():
    url = CFG.upstream + "/System/Info/Public"
    ctx = ssl._create_unverified_context() if CFG.insecure else None
    try:
        with urllib.request.urlopen(url, timeout=15, context=ctx) as r:
            info = json.loads(r.read())
        log.info("upstream OK: %s - %s version %s (Id %s)", url, info.get("ServerName"), info.get("Version"),
                 info.get("Id"))
        if not str(info.get("Version", "")).startswith("12."):
            log.warning("upstream is version %s; this shim was written for Jellyfin 12.x", info.get("Version"))
    except Exception as e:  # noqa: BLE001 - startup probe is informational only
        log.warning("could not probe upstream %s: %s (continuing anyway)", url, e)


def main():
    env = os.environ.get
    p = argparse.ArgumentParser(description="Jellyfin 10.11 -> 12 compatibility proxy for Ombi")
    p.add_argument("--upstream", default=env("OMBIFIX_UPSTREAM"), help="Jellyfin 12 base URL")
    p.add_argument("--host", default=env("OMBIFIX_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(env("OMBIFIX_PORT", "8097")))
    p.add_argument("--base-path", default=env("OMBIFIX_BASE_PATH", ""),
                   help="path prefix Ombi puts before API paths (Ombi's Jellyfin 'Base URL')")
    p.add_argument("--insecure", action="store_true", default=env("OMBIFIX_INSECURE") == "1")
    p.add_argument("--timeout", type=float, default=float(env("OMBIFIX_TIMEOUT", "300")))
    p.add_argument("--log-body-max", type=int, default=int(env("OMBIFIX_LOG_BODY_MAX", "4000")))
    p.add_argument("--log-secrets", action="store_true", default=env("OMBIFIX_LOG_SECRETS") == "1")
    args = p.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(threadName)s %(message)s")

    if not args.upstream:
        p.error("--upstream (or OMBIFIX_UPSTREAM) is required, e.g. https://jellyfin.example.com")

    CFG.upstream = args.upstream.rstrip("/")
    CFG.base_path = ("/" + args.base_path.strip("/")) if args.base_path.strip("/") else ""
    CFG.insecure = args.insecure
    CFG.timeout = args.timeout
    CFG.log_body_max = args.log_body_max
    CFG.log_secrets = args.log_secrets

    log.info("OmbiFix starting: listen=%s:%d upstream=%s base_path=%r insecure=%s timeout=%ss "
             "log_body_max=%d log_secrets=%s", args.host, args.port, CFG.upstream, CFG.base_path, CFG.insecure,
             CFG.timeout, CFG.log_body_max, CFG.log_secrets)
    for method, pattern, name in ROUTES:
        log.info("route: %-4s %s (%s)", method, pattern.replace(_ID, "{id}"), name)
    probe_upstream()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    log.info("listening on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
