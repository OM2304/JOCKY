"""JOCKY controller -- central management interface (PS: "handle multiple
system analysis simultaneously using central management interface").

A dependency-free HTTP server that:
  - queues tasks: each task is an encrypted `.jxp` payload the clients pull;
  - hands the payload to *any* number of clients (task fan-out);
  - ingests encrypted findings (logged to var/reports/ on the controller
    side only -- the clients never persist anything);
  - exposes a dead-drop surface (`/agentdrop/...`) that models the
    "legitimate cloud API" relay from transport.py.

Run:
    python agents/controller.py init        # prepare var/ dirs
    python agents/controller.py add triage.jxp --tag triage
    python agents/controller.py serve --port 8000
    python agents/controller.py mockcdn     # host:port of the lab CDN

Security notes (lab/deployment): TLS in front (the PS wants CDN-fronted
HTTPS; in the lab we demo the Host-routing semantics with the MockCDN).
Bearer tokens are compared in constant time. Payloads are protected
end-to-end by JYCRYPT1 -- the controller never sees task plaintext keys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.common import now_iso, task_id, sha256_hex  # noqa: E402

VERSION = "0.1"
VAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "var")


class ControllerState:
    def __init__(self, token: str):
        self.token = token
        self.tasks: dict = {}          # id -> meta
        self.drops: dict = {}          # id -> bytes (dead-drop blobs)
        os.makedirs(os.path.join(VAR, "reports"), exist_ok=True)
        self._loaded: set = set()

    def refresh(self):
        """Pick up tasks queued via `controller add` since boot."""
        repo = os.path.join(VAR, "registry.json")
        if not os.path.exists(repo):
            return
        reg = json.load(open(repo))
        for tid, meta in reg.get("tasks", {}).items():
            if tid in self._loaded:
                continue
            pth = os.path.join(VAR, "tasks", f"{tid}.jxp")
            if os.path.exists(pth):
                self.tasks[tid] = {**meta, "payload": open(pth, "rb").read(),
                                   "taken": False}
                self._loaded.add(tid)


class Handler(http.server.BaseHTTPRequestHandler):
    state: ControllerState = None  # set by serve()

    # ---- plumbing -----------------------------------------------------
    def _auth_ok(self) -> bool:
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return hmac.compare_digest(token, self.state.token or "")

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-JOCKY-Build", "JY_IMG01")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def log_message(self, *a):
        pass  # quiet unless --verbose

    # ---- routes -------------------------------------------------------
    def do_PING(self):  # custom verb used by the demo client
        self._json(200, {"pong": True, "ts": now_iso(),
                         "front": self.headers.get("Host", "")})

    def do_GET(self):
        st: ControllerState = self.state
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        p = self.path
        if p == "/api/v1/ping":
            return self._json(200, {"ok": True, "version": VERSION,
                                    "ts": now_iso(),
                                    "front": self.headers.get("Host", "")})
        if p == "/api/v1/task":
            st.refresh()
            for tid, meta in st.tasks.items():
                if not meta.get("taken"):
                    meta["taken"] = time.time()
                    return self._json(200, {"task": tid, "tag": meta.get("tag")})
            return self._json(404, {"task": None})
        if p.startswith("/api/v1/task/"):
            tid = p.rsplit("/", 1)[-1]
            meta = st.tasks.get(tid)
            if not meta:
                return self._json(404, {"error": "no such task"})
            return self._send(200, meta["payload"], "application/octet-stream")
        if p.startswith("/api/v1/report/"):
            tid = p.rsplit("/", 1)[-1]
            return self._json(200, {"task": tid, "reports":
                                    [f for f in os.listdir(os.path.join(VAR, "reports"))
                                     if f.startswith(tid + "_")]})
        if p.startswith("/agentdrop/get/"):
            did = p.rsplit("/", 1)[-1]
            blob = st.drops.get(did)
            return self._send(200, blob, "application/octet-stream") if blob \
                else self._json(404, {"error": "drop not found"})
        return self._json(404, {"error": "unknown route"})

    def do_POST(self):
        st: ControllerState = self.state
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        p = self.path
        if p == "/api/v1/report":
            try:
                rep = json.loads(self._read_body().decode("utf-8"))
            except Exception:
                return self._json(400, {"error": "bad report json"})
            tid = str(rep.get("task", "anon"))
            agent = str(rep.get("agent", "anon")).replace("/", "_")
            fn = os.path.join(VAR, "reports", f"{tid}_{agent}_{time.time_ns() // 1_000_000}.json")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(json.dumps(rep, indent=2))
            return self._json(200, {"stored": os.path.basename(fn)})
        if p.startswith("/agentdrop/put/"):
            did = p.rsplit("/", 1)[-1]
            st.drops[did] = self._read_body()
            return self._json(200, {"drop": did, "bytes": len(st.drops[did])})
        return self._json(404, {"error": "unknown route"})


# ---------------------------------------------------------------------------
def add_task(payload_path: str, tag: str = ""):
    with open(payload_path, "rb") as f:
        payload = f.read()
    tid = task_id()
    var = os.path.join(VAR, "tasks")
    os.makedirs(var, exist_ok=True)
    with open(os.path.join(var, f"{tid}.jxp"), "wb") as f:
        f.write(payload)
    repo = os.path.join(VAR, "registry.json")
    reg = json.load(open(repo)) if os.path.exists(repo) else {"tasks": {}}
    reg["tasks"][tid] = {"tag": tag or "untagged", "sha256": sha256_hex(payload),
                         "ts": now_iso()}
    json.dump(reg, open(repo, "w"), indent=2)
    print(f"task {tid}  tag={tag or 'untagged'}  sha256={sha256_hex(payload)[:16]}  {len(payload)}B")


def serve(port: int, token: str, verbose: bool = False):
    repo = os.path.join(VAR, "registry.json")
    reg = json.load(open(repo)) if os.path.exists(repo) else {"tasks": {}}
    state = ControllerState(token)
    state.refresh()
    Handler.state = state
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    print(f"[controller] listening on :{port}  tasks={len(state.tasks)}  "
          f"token={'yes' if token else 'none'}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(prog="jocky-controller", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s0 = sub.add_parser("init")
    s0.set_defaults(fn=lambda a: os.makedirs(os.path.join(VAR, "tasks"), exist_ok=True))

    s1 = sub.add_parser("add")
    s1.add_argument("payload")
    s1.add_argument("--tag", default="")
    s1.set_defaults(fn=lambda a: add_task(a.payload, a.tag))

    s2 = sub.add_parser("serve")
    s2.add_argument("--port", type=int, default=8000)
    s2.add_argument("--token", default="")
    s2.add_argument("-v", "--verbose", action="store_true")
    s2.set_defaults(fn=lambda a: serve(a.port, a.token, a.verbose))

    s3 = sub.add_parser("mockcdn")
    s3.add_argument("--port", type=int, default=9000)
    s3.add_argument("--origin", default="127.0.0.1:8000")
    s3.set_defaults(fn=lambda a: _mockcdn(a.port, a.origin))

    args = p.parse_args(argv)
    return args.fn(args)


def _mockcdn(port: int, origin: str):
    from agents.transport import start_mock_cdn
    host, p = origin.split(":")
    th = start_mock_cdn(port, (host, int(p)))
    print(f"[mock-cdn] host-header router on :{port} -> origin {origin}")
    th.join()


if __name__ == "__main__":
    sys.exit(main())