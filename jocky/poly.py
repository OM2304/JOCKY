"""Polymorphic engine -- the heart of requirement #2.

Every build produced from the same JOCKY source is structurally different:

  1. **Opcode permutation** -- each build gets a fresh bijective shuffle of
     the opcode table; CODE bytes are emitted with the *permuted* ids and
     the OPTS section carries the table so the VM can decode them.
  2. **Dead-code injection** -- random junk NOP instructions are woven
     between real instructions; jump targets are re-mapped through the
     index translation table so semantics are preserved.
  3. **Constant-pool shuffle** -- the pool is reordered per build and every
     PUSH/LOAD/STORE/iterator operand is rewritten to the new ids.

Net effect: N builds of the same script have N distinct sha256 hashes and
non-overlapping byte layouts (no static signature to match), while every
build executes identically. This is the "automated polymorphic engine"
called for in the SIH problem statement.
"""

from __future__ import annotations

import copy
import random
from typing import List, Optional, Tuple

from .bytecode import Image, Instr, compile_and_pack, OP_NAMES, OP_CODE


class PolymorphEngine:
    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    # ------------------------------------------------------------------
    def variant(self, parts: Tuple[List[Instr], list, list, int]) -> Image:
        """Produce one structurally-unique build of the compiled parts."""
        instrs, consts, funcs, entry = parts
        # work on a private copy: variant() must never mutate shared parts
        instrs = copy.deepcopy(instrs)
        consts = list(consts)

        # 1) fresh opcode permutation for this build
        n_ops = len(OP_NAMES)
        perm = list(range(n_ops))
        self.rng.shuffle(perm)

        # 2) weave junk NOPs between real instructions, tracking old->new
        #    instruction indices so jump operands can be re-mapped.
        mutated: List[Instr] = []
        idx_map: List[int] = []
        for ins in instrs:
            idx_map.append(len(mutated))
            for _ in range(self.rng.randint(0, 3)):
                mutated.append(Instr("NOP", self.rng.randint(0, 255)))
            mutated.append(ins)

        for ins in mutated:
            if ins.op in ("JMP", "JZ", "JNZ") and ins.operand >= 0:
                ins.operand = idx_map[ins.operand]

        # 2a) function start addresses are instruction indices in the ORIGINAL
        #     stream; translate them into the post-NOP index space first so
        #     the block shuffling below can re-map them together with jumps.
        funcs = [(name, nparams, params, idx_map[addr])
                 for name, nparams, params, addr in funcs]

        # 2b) basic-block shuffling + jump threading (PS: "alters basic
        #     control-flow graphs"). Blocks are split at branch targets,
        #     function entries and post-transfer boundaries, then emitted
        #     in a fresh random order; fall-through edges broken by the
        #     shuffle get an explicit JMP threaded in so semantics are
        #     preserved bit-for-bit.
        mutated, funcs = self._shuffle_blocks(mutated, funcs)

        # 2c) token mutation (PS: "token generation"): function symbol
        #     names get a fresh per-build suffix. CALL uses FUNC indices,
        #     so renames touch only the symbol surface -- behaviour and
        #     bytecode semantics are unchanged. The new names are added
        #     to the constant pool so FUNC entries can reference them.
        renamed: List[Tuple[str, int, List[str], int]] = []
        for name, nparams, params, addr in funcs:
            new_name = f"{name}_{self.rng.getrandbits(16):04x}"
            if new_name not in consts:
                consts.append(new_name)
            renamed.append((new_name, nparams, params, addr))
        funcs = renamed

        # 3) shuffle the constant pool and rewrite const-id operands
        order = list(range(len(consts)))
        self.rng.shuffle(order)
        remap = {old: new for new, old in enumerate(order)}
        new_consts = [consts[i] for i in order]
        for ins in mutated:
            if ins.op in ("PUSH", "LOAD", "STORE", "ITERMK", "ITERNX"):
                ins.operand = remap[ins.operand]

        return compile_and_pack(mutated, new_consts, funcs, entry,
                                perm_table=perm)

    # ------------------------------------------------------------------
    def _shuffle_blocks(self, mutated: List[Instr], funcs):
        """Basic-block reordering with explicit jump threading.

        Semantics-preserving by construction: every original instruction is
        emitted exactly once; the only new instructions are JMPs threaded in
        to recreate fall-through edges broken by the reordering. Returns the
        rewritten instruction list and funcs with updated entry addresses.
        """
        n = len(mutated)
        if n == 0:
            return mutated, funcs

        # -- split into basic blocks (branch targets / func entries /
        #    instructions right after an unconditional transfer) ----------
        boundaries = {0}
        for i, ins in enumerate(mutated):
            if ins.op in ("JMP", "JZ", "JNZ") and 0 <= ins.operand < n:
                boundaries.add(ins.operand)
            if ins.op in ("JMP", "RET", "HALT") and i + 1 < n:
                boundaries.add(i + 1)
        for _name, _np, _params, addr in funcs:
            if 0 <= addr < n:
                boundaries.add(addr)
        starts = sorted(boundaries)
        blocks = [(s, starts[k + 1] if k + 1 < len(starts) else n)
                  for k, s in enumerate(starts)]
        nblocks = len(blocks)

        # -- fall-through successor of each block, in original order -----
        def fallthrough(bi: int) -> Optional[int]:
            _s, e = blocks[bi]
            if mutated[e - 1].op in ("JMP", "RET", "HALT"):
                return None
            return bi + 1 if bi + 1 < nblocks else None

        # -- fresh order; pin the first block first (nothing falls into
        #    index 0, but the entry function usually starts there) -------
        order = list(range(nblocks))
        self.rng.shuffle(order)
        order.remove(0)
        order.insert(0, 0)

        # -- emit blocks in the new order; markers for threaded JMPs -----
        new_instrs: List[Instr] = []
        is_marker: List[bool] = []
        old2new = [0] * n
        for pos, bi in enumerate(order):
            s, e = blocks[bi]
            for i in range(s, e):
                old2new[i] = len(new_instrs)
                new_instrs.append(mutated[i])
                is_marker.append(False)
            ft = fallthrough(bi)
            if ft is not None:
                # thread a JMP only if the original successor is not the
                # block that physically follows in the new layout
                next_bi = order[pos + 1] if pos + 1 < len(order) else None
                if next_bi != ft:
                    new_instrs.append(Instr("JMP", blocks[ft][0]))
                    is_marker.append(True)

        # -- patch: original jump operands -> new indices; markers too ---
        for ins, marker in zip(new_instrs, is_marker):
            if marker:
                ins.operand = old2new[ins.operand]
            elif ins.op in ("JMP", "JZ", "JNZ") and 0 <= ins.operand < n:
                ins.operand = old2new[ins.operand]

        # -- function entries -> new indices ------------------------------
        new_funcs = [(name, nparams, params, old2new[addr])
                     for name, nparams, params, addr in funcs]
        return new_instrs, new_funcs

    def batch(self, parts: Tuple[List[Instr], list, list, int],
              count: int) -> List[Image]:
        """Generate `count` distinct builds of the same program."""
        return [self.variant(parts) for _ in range(count)]


def build_id(image: Image) -> str:
    """Short, human-readable build identifier (sha256 of the container)."""
    import hashlib
    return hashlib.sha256(image.to_bytes()).hexdigest()[:16]