"""End-to-end smoke tests for the JOCKY framework.

Covers the full pipeline:  source -> lexer -> parser -> compiler
-> image -> VM output, plus crypto round-trip and polymorphic builds
(unique hashes, identical behaviour).
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import struct

from jocky.bytecode import Image, parse_portable_consts
from jocky.compiler import compile_source
from jocky.crypto import decrypt, encrypt, new_key
from jocky.parser import parse_source
from jocky.poly import PolymorphEngine, build_id
from jocky.stdlib import NATIVE_NAMES
from jocky.vm import VM

HELLO = r'''
func greet(name) {
    return "Hello, " + name + "!";
}
func main() {
    log(greet("forensics"));
    let i = 0;
    let total = 0;
    while (i < 5) {
        total = total + i;
        i = i + 1;
    }
    log("sum(0..4) =", total);
    for (ch in "jck") {
        log("  char:", ch);
    }
}
'''


def run_src(src: str) -> str:
    """Compile source and return VM stdout."""
    vm = VM(compile_source(src, NATIVE_NAMES))
    out = io.StringIO()
    vm.out = out
    vm.run()
    return out.getvalue()


class TestPipeline(unittest.TestCase):
    def test_hello_output(self):
        out = run_src(HELLO)
        self.assertIn("Hello, forensics!", out)
        self.assertIn("sum(0..4) = 10", out)
        for ch in "jck":
            self.assertIn(f"  char: {ch}", out)

    def test_functions_and_params(self):
        out = run_src('''
func add(a, b) {
    return a + b;
}
func main() {
    log("result:", add(2, 3));
}
''')
        self.assertIn("result: 5", out)

    def test_branching(self):
        out = run_src('''
func main() {
    let x = 4;
    if (x > 3) {
        log("big");
    } else {
        log("small");
    }
}
''')
        self.assertIn("big", out)

    def test_loops_and_breaks(self):
        out = run_src('''
func main() {
    let i = 0;
    while (true) {
        i = i + 1;
        if (i == 3) { break; }
    }
    log("i =", i);
    let j = 0;
    for (n in "abc") {
        j = j + 1;
    }
    log("j =", j);
}
''')
        self.assertIn("i = 3", out)
        self.assertIn("j = 3", out)

    def test_string_concat_and_ops(self):
        out = run_src('''
func main() {
    log("a" + "b" + "c", 2 * 3, 7 - 1, 10 / 4, 10 % 3);
}
''')
        # ADD with str lhs -> concat; numeric ops evaluated as expressions
        self.assertIn("abc", out)


class TestImageSerialization(unittest.TestCase):
    """Image container round-trip: build -> to_bytes -> from_bytes -> run.

    Regression guard for the 4-byte section-tag bug (b"CONST" was being
    truncated to b"CONS", so every saved image failed to load).
    """

    def test_image_roundtrip(self):
        img = compile_source(HELLO, NATIVE_NAMES)
        blob = img.to_bytes()
        loaded = Image.from_bytes(blob)
        out = io.StringIO()
        vm = VM(loaded)
        vm.out = out
        vm.run()
        self.assertIn("Hello, forensics!", out.getvalue())
        self.assertEqual(loaded.build_id, img.build_id)

    def test_image_roundtrip_poly(self):
        program = parse_source(HELLO)
        comp = _compile(program)
        engine = PolymorphEngine()
        for img in engine.batch(comp, 3):
            loaded = Image.from_bytes(img.to_bytes())
            out = io.StringIO()
            vm = VM(loaded)
            vm.out = out
            vm.run()
            self.assertIn("sum(0..4) = 10", out.getvalue())

    def test_tampered_image_rejected(self):
        img = compile_source(HELLO, NATIVE_NAMES)
        blob = bytearray(img.to_bytes())
        blob[-1] ^= 0xFF  # corrupt the hash section
        loaded = Image.from_bytes(bytes(blob))
        self.assertNotEqual(loaded.build_hash, img.build_hash)


class TestPortableConsts(unittest.TestCase):
    """CPOR (portable constant pool) section drives the native Rust VM;
    it must round-trip the same constants as CPOL for any compiled image."""

    def _sections(self, blob: bytes) -> dict:
        sections = {}
        pos = 12
        while pos + 8 <= len(blob):
            tag = blob[pos:pos + 4]
            size = struct.unpack("<I", blob[pos + 4:pos + 8])[0]
            sections[tag] = blob[pos + 8:pos + 8 + size]
            pos += 8 + size
        return sections

    def test_cpor_matches_cpol(self):
        img = compile_source(HELLO, NATIVE_NAMES)
        self.assertIn(b"CPOR", img.to_bytes())
        sections = self._sections(img.to_bytes())
        cpol_consts = Image.from_bytes(img.to_bytes()).consts
        cpor_consts = parse_portable_consts(sections[b"CPOR"])
        self.assertEqual(cpol_consts, cpor_consts)

    def test_cpor_roundtrip_all_types(self):
        src = 'func main() { log("x", 1, 2.5, true, false, none); }'
        img = compile_source(src, NATIVE_NAMES)
        sections = self._sections(img.to_bytes())
        self.assertEqual(parse_portable_consts(sections[b"CPOR"]),
                         Image.from_bytes(img.to_bytes()).consts)


class TestProcCensusLinux(unittest.TestCase):
    """Regression test for the Linux /proc<pid>/stat parser.

    The comm field is wrapped in parens and may contain spaces, which used
    to shift every later field by one and crash int(state-letter) -> the
    census silently returned 0 processes on WSL/Linux (2026-09-11).
    """

    def test_procs_linux_parses_stat_with_spaces(self):
        import tempfile
        import pathlib
        from jocky.stdlib import _procs_linux_proc
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            d = root / "9999"
            d.mkdir()
            (d / "stat").write_text(
                "9999 (my app daemon) S 1 9999 9999 0 -1 4194560 "
                "123 0 0 0 0 0 0 0 20 0 1 0 5 0 0 0 0 0 0 0 0 0 0 0")
            (d / "cmdline").write_bytes(b"/usr/bin/my-app\0--serve\0")
            # non-numeric dir must be skipped, not crash
            (root / "notaproc").mkdir()
            rows = _procs_linux_proc(td)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["pid"], 9999)
            self.assertEqual(rows[0]["name"], "my app daemon")
            self.assertEqual(rows[0]["ppid"], 1)
            self.assertIn("--serve", rows[0]["cmdline"])


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self):
        key = new_key()
        blob = encrypt(b"JY_IMG01-hello-world", key)
        self.assertEqual(decrypt(blob, key), b"JY_IMG01-hello-world")

    def test_tamper_detection(self):
        key = new_key()
        blob = bytearray(encrypt(b"secret-payload", key))
        blob[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt(bytes(blob), key)


class TestPoly(unittest.TestCase):
    def test_unique_hashes_identical_behavior(self):
        program = parse_source(HELLO)
        comp = _compile(program)
        engine = PolymorphEngine()
        images = engine.batch(comp, 3)

        hashes = {hashlib.sha256(img.to_bytes()).hexdigest() for img in images}
        self.assertEqual(len(hashes), 3, "expected 3 distinct build hashes")

        outputs = set()
        for img in images:
            out = io.StringIO()
            vm = VM(img)
            vm.out = out
            vm.run()
            outputs.add(out.getvalue())
        self.assertEqual(len(outputs), 1, "all builds must behave identically")

    def test_build_id_unique(self):
        program = parse_source(HELLO)
        comp = _compile(program)
        engine = PolymorphEngine()
        ids = {build_id(img) for img in engine.batch(comp, 5)}
        self.assertGreater(len(ids), 1)


def _compile(program):
    from jocky.compiler import Compiler
    return Compiler(native_names=NATIVE_NAMES).compile_parts(program)


if __name__ == "__main__":
    unittest.main(verbosity=2)