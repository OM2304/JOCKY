"""JOCKY bytecode container format + assembler/disassembler.

Image layout (all integers little-endian unless stated):
    magic   : 8 bytes  = b'JY_IMG01'
    version : u32
    sections: repeated [tag: 4 bytes][size: u32][payload]
              payload of 'CPOL' is zlib-compressed pickle of the constant pool.

Sections (tags are exactly 4 bytes):
    OPTS : opcode permutation table (len == number of opcodes); byte i holds
           the *encoded* id used in CODE for base opcode i.  A build that
           does not permute simply stores identity.  The VM builds the
           inverse table at load time, so any bijective permutation works.
    CPOL : zlib+pickle constant pool (literals, local names, func names).
           (Named CPOL to keep the 4-byte tag constraint.)
    CODE : instruction stream. Each instruction: [u8 encoded_op][operand bytes].
           Operand width is fixed per opcode (see OP_WIDTHS).
    FUNC : function table: N : u32, then per entry:
           u8 name_id | u8 nparams | (u8 param_const_id)*nparams | u32 addr(byte offset into CODE)
    ENTR : u32 index into FUNC table for the entry function.
    HASH : 32 bytes sha256 of the canonical (unpermuted) CODE stream
           -> unique per build after polymorphic mutation.

Offsets stored in CODE are absolute byte offsets into the CODE payload,
computed after all instructions are sized, because jumps patch
instruction indices *before* bytes are assigned. The VM indexes CODE as
a bytes object, so this keeps the interpreter dependency-free and fast.
"""

from __future__ import annotations

import hashlib
import pickle
import struct
import zlib
from typing import Dict, List, Optional, Tuple

MAGIC = b"JY_IMG01"
VERSION = 1

# ---------------------------------------------------------------------------
# Portable constant pool (CPOR section)
#
# CPOL (zlib+pickle) is the canonical Python encoding. The native Rust VM
# cannot decode pickle, so every image also carries a CPOR section with the
# same constants in a trivial, dependency-free binary form. Python ignores
# CPOR; bytecode round-trips and polymorphic hashing are unaffected.
#
# CPOR payload layout (little-endian):
#     u32 version (=1) | u32 count | per entry: u8 type | u32 len | payload
#     type 0 = None, 1 = bool(1B), 2 = int(8B i64 LE), 3 = float(8B f64 LE),
#     4 = str(utf-8).
# ---------------------------------------------------------------------------

CPOR_VERSION = 1
_C_NONE = 0
_C_BOOL = 1
_C_INT = 2
_C_FLOAT = 3
_C_STR = 4


def _portable_consts(consts: list) -> bytes:
    """Encode the constant pool for the native VM (CPOR section)."""
    out = bytearray(struct.pack("<II", CPOR_VERSION, len(consts)))
    for value in consts:
        if value is None:
            out += bytes([_C_NONE]) + struct.pack("<I", 0)
        elif isinstance(value, bool):
            out += bytes([_C_BOOL]) + struct.pack("<I", 1) + bytes([int(value)])
        elif isinstance(value, int):
            packed = value.to_bytes(8, "little", signed=True)
            if int.from_bytes(packed, "little", signed=True) != value:
                raise BytecodeError(
                    f"constant int {value} exceeds native i64 range; "
                    "portable (Rust VM) images are limited to 64-bit integers")
            out += bytes([_C_INT]) + struct.pack("<I", 8) + packed
        elif isinstance(value, float):
            out += bytes([_C_FLOAT]) + struct.pack("<I", 8) + struct.pack("<d", value)
        elif isinstance(value, str):
            data = value.encode("utf-8")
            out += bytes([_C_STR]) + struct.pack("<I", len(data)) + data
        else:
            raise BytecodeError(
                f"constant of type {type(value).__name__} not representable "
                "in portable CPOR section")
    return bytes(out)


def parse_portable_consts(payload: bytes) -> list:
    """Decode a CPOR section back into the constant list (used by tests
    and by external tooling; the Rust VM implements the same layout)."""
    if len(payload) < 8:
        raise BytecodeError("CPOR section too short")
    ver, n = struct.unpack("<II", payload[:8])
    if ver != CPOR_VERSION:
        raise BytecodeError(f"unsupported CPOR version {ver}")
    pos = 8
    consts = []
    for _ in range(n):
        if pos + 5 > len(payload):
            raise BytecodeError("CPOR section truncated")
        ctype = payload[pos]
        length = struct.unpack("<I", payload[pos + 1:pos + 5])[0]
        pos += 5
        data = payload[pos:pos + length]
        if len(data) != length:
            raise BytecodeError(f"truncated CPOR entry (type {ctype})")
        pos += length
        if ctype == _C_NONE:
            value = None
        elif ctype == _C_BOOL:
            value = bool(data[0])
        elif ctype == _C_INT:
            value = int.from_bytes(data, "little", signed=True)
        elif ctype == _C_FLOAT:
            value = struct.unpack("<d", data)[0]
        elif ctype == _C_STR:
            value = data.decode("utf-8")
        else:
            raise BytecodeError(f"unknown CPOR constant type {ctype}")
        consts.append(value)
    return consts

# ---------------------------------------------------------------------------
# Opcode table: name -> (code, operand_width_bytes)
# Keep NOP and HALT reserved so the polymorphic engine can always reference them.
# ---------------------------------------------------------------------------

_OP_DEFS: List[Tuple[str, int]] = [
    ("NOP", 1),      # 0  junk operand; skipped by the VM
    ("PUSH", 1),     # 1  push constant pool[id]
    ("LOAD", 1),     # 2  push local slot[id]
    ("STORE", 1),    # 3  pop -> local slot[id]
    ("JMP", 4),      # 4  jump to absolute byte offset
    ("JZ", 4),       # 5  pop; jump if falsy
    ("JNZ", 4),      # 6  pop; jump if truthy
    ("CALL", 1),     # 7  call user function (FUNC index)
    ("NAT", 1),      # 8  call native (stdlib index)
    ("RET", 0),      # 9  return, popping the result
    ("PUSHARG", 0),  # 10 push current arg count marker (used by CALL)
    ("ITERMK", 1),   # 11 pop iterable -> iterator stored in slot[id]
    ("ITERNX", 1),   # 12 advance iterator in slot[id]; push element or None
    ("POP", 0),      # 13 discard top of stack
    ("HALT", 0),     # 14 stop VM, result = top of stack (or None)
    # arithmetic / comparison
    ("ADD", 0), ("SUB", 0), ("MUL", 0), ("DIV", 0), ("MOD", 0),
    ("NEG", 0),
    ("EQ", 0), ("NE", 0), ("LT", 0), ("GT", 0), ("LE", 0), ("GE", 0),
    ("AND", 0), ("OR", 0), ("NOT", 0),
]

OP_NAMES: List[str] = [name for name, _ in _OP_DEFS]
OP_CODE: Dict[str, int] = {name: idx for idx, (name, _) in enumerate(_OP_DEFS)}
OP_WIDTHS: List[int] = [width for _, width in _OP_DEFS]


class BytecodeError(Exception):
    pass


# ---------------------------------------------------------------------------
# Assembler helpers (used by the compiler / polymorphic engine)
# ---------------------------------------------------------------------------

class Instr:
    __slots__ = ("op", "operand")

    def __init__(self, op: str, operand: int = 0):
        if op not in OP_CODE:
            raise BytecodeError(f"unknown opcode {op!r}")
        self.op = op
        self.operand = operand

    def width(self) -> int:
        return OP_WIDTHS[OP_CODE[self.op]]

    def size_bytes(self) -> int:
        return 1 + self.width()

    def __repr__(self):  # pragma: no cover
        return f"Instr({self.op}, {self.operand})"


def encode_instruction(instr: Instr, perm_table: Optional[List[int]] = None) -> bytes:
    """Serialize one instruction. `perm_table` maps base opcode -> encoded id."""
    base = OP_CODE[instr.op]
    enc = perm_table[base] if perm_table else base
    if not (0 <= enc < 256):
        raise BytecodeError(f"opcode id {enc} out of byte range")
    width = instr.width()
    operand = instr.operand & 0xFFFFFFFF
    if width == 0:
        return bytes([enc])
    return bytes([enc]) + operand.to_bytes(width, "little")


def disassemble(code: bytes, perm_table: Optional[List[int]] = None) -> List[str]:
    """Human-readable listing. Inverse table maps encoded -> base opcode."""
    inv = None
    if perm_table is not None:
        inv = [0] * len(perm_table)
        for base, enc in enumerate(perm_table):
            inv[enc] = base
    out: List[str] = []
    i = 0
    addr = 0
    while i < len(code):
        enc = code[i]
        base = inv[enc] if inv is not None else enc
        if base is None or base >= len(OP_NAMES):
            out.append(f"{addr:04x}: <bad op {enc:#x}>")
            i += 1
            addr += 1
            continue
        name = OP_NAMES[base]
        width = OP_WIDTHS[base]
        operand = 0
        if width:
            operand = int.from_bytes(code[i + 1:i + 1 + width], "little")
        show = name
        if width:
            show += f" {operand}"
        out.append(f"{addr:04x}: {show}")
        i += 1 + width
        addr += 1 + width
    return out


# ---------------------------------------------------------------------------
# Image container
# ---------------------------------------------------------------------------

class Image:
    """In-memory compiled JOCKY program."""

    def __init__(self, *, code: bytes, consts: list, funcs: List[Tuple[str, int, List[str], int]],
                 entry: int, perm_table: Optional[List[int]] = None,
                 build_hash: Optional[bytes] = None, build_id: Optional[str] = None):
        # funcs: list of (name, nparams, param_names, code_offset)
        self.code = code
        self.consts = consts
        self.funcs = funcs
        self.entry = entry
        self.perm_table = perm_table or list(range(len(OP_NAMES)))
        self.build_hash = build_hash
        self.build_id = build_id

    # -- serialization -------------------------------------------------
    def to_bytes(self) -> bytes:
        fdata = bytearray()
        fdata += struct.pack("<I", len(self.funcs))
        for name, nparams, params, addr in self.funcs:
            fdata += bytes([self._const_id(name), nparams])
            fdata += bytes(self._const_id(p) for p in params)
            fdata += struct.pack("<I", addr)

        sections = [
            (b"OPTS", bytes(self.perm_table)),
            (b"CPOL", zlib.compress(pickle.dumps(self.consts, protocol=4), 9)),
            (b"CPOR", _portable_consts(self.consts)),
            (b"CODE", self.code),
            (b"FUNC", bytes(fdata)),
            (b"ENTR", struct.pack("<I", self.entry)),
            (b"HASH", self.build_hash or hashlib.sha256(self.code).digest()),
        ]
        out = bytearray(MAGIC + struct.pack("<I", VERSION))
        for tag, payload in sections:
            out += struct.pack("<4sI", tag, len(payload))
            out += payload
        return bytes(out)

    def _const_id(self, value) -> int:
        try:
            return self.consts.index(value)
        except ValueError:
            raise BytecodeError(f"constant {value!r} not in pool")

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Image":
        if blob[:8] != MAGIC:
            raise BytecodeError("bad magic: not a JOCKY image")
        ver = struct.unpack("<I", blob[8:12])[0]
        if ver != VERSION:
            raise BytecodeError(f"unsupported image version {ver}")
        pos = 12
        sections: Dict[bytes, bytes] = {}
        while pos + 8 <= len(blob):
            tag = blob[pos:pos + 4]
            size = struct.unpack("<I", blob[pos + 4:pos + 8])[0]
            payload = blob[pos + 8:pos + 8 + size]
            if len(payload) != size:
                raise BytecodeError(f"truncated section {tag!r}")
            sections[tag] = payload
            pos += 8 + size

        perm = list(sections.get(b"OPTS", bytes(range(len(OP_NAMES)))))
        consts = pickle.loads(zlib.decompress(sections[b"CPOL"]))
        code = sections[b"CODE"]
        fdata = sections[b"FUNC"]
        n = struct.unpack("<I", fdata[:4])[0]
        funcs = []
        off = 4
        for _ in range(n):
            name_id = fdata[off]
            nparams = fdata[off + 1]
            off += 2
            params = [consts[fdata[off + i]] for i in range(nparams)]
            off += nparams
            addr = struct.unpack("<I", fdata[off:off + 4])[0]
            funcs.append((consts[name_id], nparams, params, addr))
            off += 4
        entry = struct.unpack("<I", sections[b"ENTR"])[0]
        build_hash = sections.get(b"HASH")
        build_id = build_hash.hex()[:16] if build_hash else None
        return cls(code=code, consts=consts, funcs=funcs, entry=entry,
                   perm_table=perm, build_hash=build_hash, build_id=build_id)

    def disasm(self) -> List[str]:
        return disassemble(self.code, self.perm_table)


def compile_and_pack(instructions: List[Instr], consts: list,
                     funcs: List[Tuple[str, int, List[str], int]], entry: int,
                     perm_table: Optional[List[int]] = None) -> Image:
    """Assemble raw instructions into a packed Image (byte offsets assigned)."""
    if perm_table is None:
        perm_table = list(range(len(OP_NAMES)))
    # assign byte offsets
    offsets: List[int] = []
    cur = 0
    for ins in instructions:
        offsets.append(cur)
        cur += ins.size_bytes()
    # function start addresses are still instruction indices here;
    # translate them to byte offsets now that sizes are known.
    funcs = [(name, nparams, params, offsets[addr])
             for name, nparams, params, addr in funcs]
    code = bytearray()
    for ins, off in zip(instructions, offsets):
        # patch jump targets (they were recorded as instruction indices)
        op = ins.op
        if op in ("JMP", "JZ", "JNZ"):
            code += encode_instruction(Instr(op, offsets[ins.operand]), perm_table)
        else:
            code += encode_instruction(ins, perm_table)
    build_hash = hashlib.sha256(bytes(code)).digest()
    return Image(code=bytes(code), consts=consts, funcs=funcs, entry=entry,
                 perm_table=perm_table, build_hash=build_hash,
                 build_id=build_hash.hex()[:16])