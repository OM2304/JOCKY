"""JOCKY command-line interface.

    python -m jocky build  script.jck -o out.jcx      compile to image
    python -m jocky run    script.jck                 compile + run in memory
    python -m jocky run    out.jcx                    run a saved image
    python -m jocky poly   script.jck -n 10 -o dir/   generate N polymorphic
                                                      variants (unique hashes)
    python -m jocky enc    script.jck -o p.jxp -k key encrypt a payload image
    python -m jocky run    p.jxp -k key               decrypt in memory + run
    python -m jocky info   out.jcx                    image internals + disasm
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

from . import __version__
from .bytecode import Image
from .compiler import Compiler, compile_source
from .crypto import decrypt, encrypt, new_key
from .parser import parse_source
from .poly import PolymorphEngine, build_id
from .stdlib import NATIVE_NAMES
from .vm import VM


def _err(msg: str) -> int:
    print(f"jocky: error: {msg}", file=sys.stderr)
    return 1


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write(path: str, data: bytes) -> None:
    # Create parent directories so `-o` paths like builds/out.jcx work
    # even when the directory does not exist yet (demo/CI safety).
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _compile_parts(path: str):
    src = _read(path).decode("utf-8")
    program = parse_source(src)
    return Compiler(native_names=NATIVE_NAMES).compile_parts(program)


def _compile(path: str) -> Image:
    src = _read(path).decode("utf-8")
    return compile_source(src, NATIVE_NAMES)


# ---------------------------------------------------------------------------
def cmd_build(args) -> int:
    img = _compile(args.script)
    out = args.out or os.path.splitext(args.script)[0] + ".jcx"
    _write(out, img.to_bytes())
    print(f"built  {out}  ({len(img.to_bytes())} bytes, "
          f"sha256={hashlib.sha256(img.to_bytes()).hexdigest()[:16]}, "
          f"{len(img.funcs)} function(s))")
    return 0


def cmd_run(args) -> int:
    blob = _read(args.input)
    if args.key:
        blob = decrypt(blob, bytes.fromhex(args.key))
    try:
        img = Image.from_bytes(blob)
    except Exception as e:
        if args.input.endswith((".jck", ".txt")):
            img = compile_source(blob.decode("utf-8"), NATIVE_NAMES)
        else:
            return _err(str(e))
    vm = VM(img)
    try:
        result = vm.run()
    except Exception as e:
        return _err(f"VM: {e}")
    if args.verbose:
        print(f"[jocky] build_id={img.build_id} funcs={len(img.funcs)} "
              f"code={len(img.code)}B result={result!r}",
              file=sys.stderr)
    return 0


def cmd_poly(args) -> int:
    parts = _compile_parts(args.script)
    outdir = args.out or "builds"
    os.makedirs(outdir, exist_ok=True)
    engine = PolymorphEngine()
    images = engine.batch(parts, args.count)
    hashes = []
    for i, img in enumerate(images, 1):
        blob = img.to_bytes()
        name = os.path.join(outdir, f"{os.path.splitext(os.path.basename(args.script))[0]}_b{i:02d}.jcx")
        _write(name, blob)
        h = hashlib.sha256(blob).hexdigest()
        hashes.append(h)
        print(f"  build {i:02d}: {name}  sha256={h[:16]}  {len(blob)}B")
    uniq = len(set(hashes))
    print(f"[jocky] {len(images)} builds, {uniq} unique hashes "
          f"({'OK' if uniq == len(images) else 'COLLISION!'})")
    return 0


def cmd_enc(args) -> int:
    img = _compile(args.script)
    key = bytes.fromhex(args.key) if args.key else new_key()
    blob = encrypt(img.to_bytes(), key)
    out = args.out or os.path.splitext(args.script)[0] + ".jxp"
    _write(out, blob)
    print(f"encrypted {out} ({len(blob)} bytes)")
    print(f"key (hex): {key.hex()}")
    return 0


def cmd_info(args) -> int:
    blob = _read(args.input)
    try:
        img = Image.from_bytes(blob)
    except Exception as e:
        # accept .jck sources too, exactly like `run` does
        if args.input.endswith((".jck", ".txt")):
            img = compile_source(blob.decode("utf-8"), NATIVE_NAMES)
        else:
            return _err(str(e))
    print(f"build_id : {img.build_id}")
    print(f"magic    : JY_IMG01 v1")
    print(f"code     : {len(img.code)} bytes")
    print(f"consts   : {len(img.consts)} entries")
    print(f"entry    : #{img.entry} {img.funcs[img.entry][0]}")
    print("functions:")
    for i, (name, nparams, params, addr) in enumerate(img.funcs):
        print(f"  {i:2d}  {name}({', '.join(params)}) @ {addr:#06x}")
    if args.disasm:
        print("\ndisassembly:")
        for line in img.disasm():
            print("  " + line)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="jocky",
        description=f"JOCKY forensic scripting framework v{__version__} (SIH26148)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="compile a .jck script to a .jcx image")
    b.add_argument("script")
    b.add_argument("-o", "--out")
    b.set_defaults(fn=cmd_build)

    r = sub.add_parser("run", help="run a .jck script or .jcx image in memory")
    r.add_argument("input")
    r.add_argument("-k", "--key", help="decrypt .jxp payload with hex key")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(fn=cmd_run)

    p2 = sub.add_parser("poly", help="generate polymorphic build variants")
    p2.add_argument("script")
    p2.add_argument("-n", "--count", type=int, default=10)
    p2.add_argument("-o", "--out")
    p2.set_defaults(fn=cmd_poly)

    e = sub.add_parser("enc", help="compile + encrypt a payload image")
    e.add_argument("script")
    e.add_argument("-o", "--out")
    e.add_argument("-k", "--key", help="hex key (default: random)")
    e.set_defaults(fn=cmd_enc)

    i = sub.add_parser("info", help="inspect an image file")
    i.add_argument("input")
    i.add_argument("--disasm", action="store_true")
    i.set_defaults(fn=cmd_info)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        return _err(f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    sys.exit(main())