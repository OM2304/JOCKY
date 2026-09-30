"""JOCKY stack VM: executes packed Image bytecode fully in memory.

The VM never touches disk: images are handed to it as `bytes` and decoded
section-by-section into Python objects. This is the execution core used
both by the CLI (`run`) and by the remote agent (in-memory execution of
decrypted payloads).

Calling convention:
    CALL/NAT expects a PUSHARG marker below `n` arguments on the operand
    stack. Arguments are evaluated left-to-right and pushed in order, so
    the marker sits on top. The VM pops the marker, then pops `n` values,
    reverses them, and binds them to the callee's parameters.

FUNC entries carry the parameter name const-ids, so the VM can bind
arguments without any compile-time side tables.
"""

from __future__ import annotations

import sys
from typing import Callable, List, Optional

from .bytecode import Image, OP_NAMES, OP_WIDTHS
from .stdlib import NATIVE_FUNCS

MAX_STEPS = 20_000_000
ARGMARK = object()  # sentinel pushed by PUSHARG


class VMError(Exception):
    pass


class Frame:
    __slots__ = ("name", "locals", "addr", "ret_addr")

    def __init__(self, name: str, locals_: dict, addr: int,
                 ret_addr: Optional[int]):
        self.name = name
        self.locals = locals_
        self.addr = addr
        self.ret_addr = ret_addr


class VM:
    def __init__(self, image: Image, natives: Optional[List[Callable]] = None,
                 out=None, max_steps: int = MAX_STEPS):
        self.image = image
        self.natives = natives if natives is not None else NATIVE_FUNCS
        self.out = out if out is not None else sys.stdout
        # inverse opcode table: encoded id -> base id
        self.inv = [0] * len(image.perm_table)
        for base, enc in enumerate(image.perm_table):
            self.inv[enc] = base
        self.max_steps = max_steps
        self.stack: list = []
        self.frames: List[Frame] = []
        self.pc = 0

    # ------------------------------------------------------------------
    def _pop(self):
        if not self.stack:
            raise VMError("operand stack underflow")
        return self.stack.pop()

    # ------------------------------------------------------------------
    def run(self, entry: Optional[int] = None) -> object:
        """Execute the image starting at `entry` (default: image.entry)."""
        entry = self.image.entry if entry is None else entry
        if not (0 <= entry < len(self.image.funcs)):
            raise VMError(f"bad entry function index {entry}")

        img = self.image
        name, nparams, params, addr = img.funcs[entry]
        self.frames = [Frame(name, {p: None for p in params}, addr, None)]
        self.pc = addr
        self.stack = []

        code = img.code
        consts = img.consts
        funcs = img.funcs
        natives = self.natives
        inv = self.inv
        widths = OP_WIDTHS
        steps = 0

        while True:
            if steps >= self.max_steps:
                raise VMError("step limit exceeded (infinite loop?)")
            steps += 1
            if self.pc >= len(code):
                raise VMError("program counter ran past end of code")

            enc = code[self.pc]
            base = inv[enc]
            if base >= len(OP_NAMES):
                raise VMError(f"invalid opcode {enc:#x} at {self.pc:#x}")
            width = widths[base]
            operand = 0
            if width:
                operand = int.from_bytes(
                    code[self.pc + 1:self.pc + 1 + width], "little")
            nxt = self.pc + 1 + width
            op = OP_NAMES[base]

            # --- stack / constants ------------------------------------
            if op == "NOP":
                pass
            elif op == "PUSH":
                self.stack.append(consts[operand])
            elif op == "LOAD":
                self.stack.append(self.frames[-1].locals.get(consts[operand]))
            elif op == "STORE":
                self.frames[-1].locals[consts[operand]] = self._pop()
            elif op == "POP":
                self._pop()
            elif op == "PUSHARG":
                self.stack.append(ARGMARK)

            # --- control flow -----------------------------------------
            elif op == "JMP":
                self.pc = operand
                continue
            elif op == "JZ":
                if not self._pop():
                    self.pc = operand
                    continue
            elif op == "JNZ":
                if self._pop():
                    self.pc = operand
                    continue

            # --- calls ------------------------------------------------
            elif op == "CALL":
                fname, nparams, fparams, faddr = funcs[operand]
                if len(self.stack) < nparams + 1:
                    raise VMError(
                        f"{fname}() takes {nparams} args, got "
                        f"{max(0, len(self.stack) - (1 if self.stack else 0))}")
                args = self.stack[-nparams:]
                del self.stack[-nparams:]
                if not self.stack or self.stack[-1] is not ARGMARK:
                    raise VMError("CALL without PUSHARG marker")
                self.stack.pop()          # consume the opening marker
                args.reverse()
                if len(args) != nparams:
                    raise VMError(
                        f"{fname}() takes {nparams} args, got {len(args)}")
                self.frames.append(Frame(fname, dict(zip(fparams, args)),
                                         faddr, nxt))
                self.pc = faddr
                continue
            elif op == "NAT":
                args = []
                while self.stack and self.stack[-1] is not ARGMARK:
                    args.append(self.stack.pop())
                if not self.stack or self.stack[-1] is not ARGMARK:
                    raise VMError("NAT without PUSHARG marker")
                self.stack.pop()          # consume the opening marker
                args.reverse()
                if operand >= len(natives):
                    raise VMError(f"bad native index {operand}")
                try:
                    result = natives[operand](self, args)
                except VMError:
                    raise
                except Exception as e:
                    raise VMError(f"native #{operand} failed: {e}") from e
                self.stack.append(result)
            elif op == "RET":
                result = self._pop() if self.stack else None
                if len(self.frames) == 1:
                    self.frames.pop()
                    return result
                frame = self.frames.pop()
                self.pc = frame.ret_addr
                self.stack.append(result)
                continue

            # --- iteration --------------------------------------------
            elif op == "ITERMK":
                it_name = consts[operand]
                self.frames[-1].locals[it_name] = iter(self._pop())
            elif op == "ITERNX":
                it_name = consts[operand]
                it = self.frames[-1].locals.get(it_name)
                if it is None:
                    raise VMError(f"iterator {it_name!r} not initialized")
                try:
                    self.stack.append(next(it))
                except StopIteration:
                    self.stack.append(None)

            # --- arithmetic -------------------------------------------
            elif op == "ADD":
                b, a = self._pop(), self._pop()
                self.stack.append(str(a) + str(b) if isinstance(a, str)
                                  or isinstance(b, str) else a + b)
            elif op == "SUB":
                b, a = self._pop(), self._pop()
                self.stack.append(a - b)
            elif op == "MUL":
                b, a = self._pop(), self._pop()
                self.stack.append(a * b)
            elif op == "DIV":
                b, a = self._pop(), self._pop()
                if b == 0:
                    raise VMError("division by zero")
                self.stack.append(a / b)
            elif op == "MOD":
                b, a = self._pop(), self._pop()
                if b == 0:
                    raise VMError("modulo by zero")
                self.stack.append(a % b)
            elif op == "NEG":
                self.stack.append(-self._pop())

            # --- comparison / logic -----------------------------------
            elif op == "EQ":
                b, a = self._pop(), self._pop()
                self.stack.append(a == b)
            elif op == "NE":
                b, a = self._pop(), self._pop()
                self.stack.append(a != b)
            elif op == "LT":
                b, a = self._pop(), self._pop()
                self.stack.append(a < b)
            elif op == "GT":
                b, a = self._pop(), self._pop()
                self.stack.append(a > b)
            elif op == "LE":
                b, a = self._pop(), self._pop()
                self.stack.append(a <= b)
            elif op == "GE":
                b, a = self._pop(), self._pop()
                self.stack.append(a >= b)
            elif op == "AND":
                b, a = self._pop(), self._pop()
                self.stack.append(a if not a else b)
            elif op == "OR":
                b, a = self._pop(), self._pop()
                self.stack.append(a if a else b)
            elif op == "NOT":
                self.stack.append(not self._pop())
            elif op == "HALT":
                return self.stack[-1] if self.stack else None
            else:
                raise VMError(f"unimplemented opcode {op}")

            self.pc = nxt

        raise VMError("VM exited without result")  # pragma: no cover