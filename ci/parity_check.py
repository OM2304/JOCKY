"""Cross-VM output-parity gate: Python VM vs native Rust VM (jocky-rs).

For every script listed in STRICT_PARITY the harness requires the Python VM
and the native VM to produce BYTE-IDENTICAL stdout for the same .jcx image.
Runtime-dependent scripts (netprobe: live socket counts change between runs)
are exercised in RUN_ONLY mode: both VMs must succeed with the same output
SHAPE (same line count + labels), not identical bytes.

Also cross-validates JYCRYPT1: the Python toolchain encrypts, the native VM
decrypts + executes (and, because STRICT parity covers the embedded payload,
the Rust crypto twin is proven against the Python implementation).

Usage:
    python ci/parity_check.py                # auto-locate jocky-rs.exe
    python ci/parity_check.py --bin path     # explicit native binary
Exit 0 = parity OK. Any mismatch prints a unified diff and exits 1.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# scripts whose output must be byte-identical on both VMs
STRICT_PARITY = ["examples/hello.jck", "examples/stealth.jck"]
# scripts both VMs must RUN successfully, output shape compared only
RUN_ONLY = ["examples/netprobe.jck"]

TEST_KEY = "00112233445566778899aabbccddeeff"


def find_native_bin() -> str | None:
    """Locate a built jocky-rs binary (debug or release, win or unix)."""
    pats = [
        os.path.join(ROOT, "native", "vm_rs", "target", "release", "jocky-rs*"),
        os.path.join(ROOT, "native", "vm_rs", "target", "debug", "jocky-rs*"),
    ]
    for pat in pats:
        for hit in sorted(glob.glob(pat)):
            base = os.path.basename(hit)
            if base.startswith("jocky-rs") and not base.endswith(".d"):
                return hit
    return None


def run(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                       cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


def norm_shape(text: str) -> list[str]:
    """Strip digits from output lines so volatile counts compare as shape."""
    out = []
    for line in text.splitlines():
        out.append("".join("#" if c.isdigit() else c for c in line))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=None, help="path to jocky-rs binary")
    a = ap.parse_args(argv)

    native = a.bin or find_native_bin()
    if not native:
        print("[parity] native VM binary not found -- build it first:")
        print("         cd native/vm_rs && cargo build --release")
        return 2

    py = sys.executable or "python"
    tmp = tempfile.mkdtemp(prefix="jocky_parity_")
    failures = 0
    checks = 0

    def note(ok: bool, label: str, detail: str = "") -> None:
        nonlocal failures, checks
        checks += 1
        mark = "[ok]" if ok else "[FAIL]"
        print(f"  {mark} {label}" + (f"  ({detail})" if detail else ""))
        if not ok:
            failures += 1

    for script in STRICT_PARITY + RUN_ONLY:
        name = os.path.splitext(os.path.basename(script))[0]
        jcx = os.path.join(tmp, f"{name}.jcx")
        rc, _, _ = run([py, "-m", "jocky", "build", script, "-o", jcx])
        if rc != 0:
            note(False, f"{name}: build")
            continue
        rc_py, out_py, _ = run([py, "-m", "jocky", "run", jcx])
        rc_rs, out_rs, _ = run([native, jcx])
        if rc_py != 0 or rc_rs != 0:
            note(False, f"{name}: execution "
                        f"(py rc={rc_py}, native rc={rc_rs})")
            continue
        if script in STRICT_PARITY:
            h_py = hashlib.sha256(out_py.encode()).hexdigest()[:16]
            h_rs = hashlib.sha256(out_rs.encode()).hexdigest()[:16]
            note(h_py == h_rs, f"{name}: byte-identical output",
                 f"sha {h_py} == {h_rs}" if h_py == h_rs
                 else f"py {h_py} != native {h_rs}")
            if h_py != h_rs:
                import difflib
                for line in list(difflib.unified_diff(
                        out_py.splitlines(), out_rs.splitlines(),
                        "python-vm", "native-vm", lineterm=""))[:20]:
                    print("    " + line)
        else:
            shape_py, shape_rs = norm_shape(out_py), norm_shape(out_rs)
            note(shape_py == shape_rs, f"{name}: same output shape "
                                       f"(live data, counts may differ)",
                 f"{len(out_py.splitlines())} lines vs "
                 f"{len(out_rs.splitlines())} lines")

    # JYCRYPT1 cross-validation: Python encrypts -> native decrypts + runs
    jxp = os.path.join(tmp, "hello.jxp")
    rc, _, _ = run([py, "-m", "jocky", "enc", "examples/hello.jck",
                   "-o", jxp, "-k", TEST_KEY])
    if rc != 0:
        note(False, "jycrypt1: python encrypt")
    else:
        rc_rs, out_rs, err_rs = run([native, jxp, "-k", TEST_KEY])
        _, out_py, _ = run([py, "-m", "jocky", "run", jxp, "-k", TEST_KEY])
        note(rc_rs == 0 and out_rs == out_py and "SELF-TEST" in out_rs,
             "jycrypt1: python-encrypted -> native-decrypted -> executed",
             f"sha {hashlib.sha256(out_rs.encode()).hexdigest()[:16]}")

    # tamper rejection on the native side
    if os.path.exists(jxp):
        blob = bytearray(open(jxp, "rb").read())
        blob[-1] ^= 0xFF
        bad = os.path.join(tmp, "bad.jxp")
        open(bad, "wb").write(bytes(blob))
        rc_rs, _, err_rs = run([native, bad, "-k", TEST_KEY])
        note(rc_rs != 0 and "integrity" in (err_rs or ""),
             "jycrypt1: tampered blob rejected by native VM",
             (err_rs or "").strip())

    # shuffled-CFG polymorphic variant: native VM must execute a build
    # produced by the full poly pipeline (block shuffle + jump threading +
    # token mutation) exactly like the Python VM does.
    poly_dir = os.path.join(tmp, "poly")
    rc, _, _ = run([py, "-m", "jocky", "poly", "examples/hello.jck",
                    "-n", "2", "-o", poly_dir])
    variant = os.path.join(poly_dir, "hello_b01.jcx")
    if rc != 0 or not os.path.exists(variant):
        note(False, "poly variant: build")
    else:
        rc_py, out_py, _ = run([py, "-m", "jocky", "run", variant])
        rc_rs, out_rs, _ = run([native, variant])
        note(rc_py == 0 and rc_rs == 0 and out_py == out_rs
             and "SELF-TEST" in out_py,
             "poly variant (shuffled CFG + mangled symbols): "
             "byte-identical on both VMs")

    print(f"\n[parity] {checks - failures}/{checks} checks passed "
          f"(native: {os.path.relpath(native, ROOT)})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
