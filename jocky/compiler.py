"""JOCKY compiler: AST -> instruction list -> packed Image.

The compiler emits a flat list of `Instr` objects that share one global
constant pool and one global instruction stream. Function bodies are laid
out back-to-back; the FUNC table stores each function's byte offset into
that stream, so the VM can jump between functions with no relocation.

Jump strategy: during compilation, JMP/JZ/JNZ operands hold *label names*.
Labels are resolved to instruction indices when a function body finishes,
and `compile_and_pack` later translates instruction indices to absolute
byte offsets. This matches the polymorphic engine, which needs the
instruction stream (not raw bytes) so it can inject dead code and
permute opcodes *before* offsets are fixed.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .ast_nodes import (
    Assign, BinOp, Break, Call, Continue, For, FuncDef, If, Literal,
    Node, Program, Return, UnaryOp, VarRef, While,
)
from .bytecode import Image, Instr, compile_and_pack


class CompileError(Exception):
    pass


# instruction opcodes used by the compiler
_BINOP_OPCODE = {
    "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD",
    "==": "EQ", "!=": "NE", "<": "LT", ">": "GT", "<=": "LE", ">=": "GE",
    "and": "AND", "or": "OR",
}


class Compiler:
    def __init__(self, native_names: Optional[List[str]] = None):
        self.native_index: Dict[str, int] = {
            name: i for i, name in enumerate(native_names or [])
        }
        self.consts: list = []
        self.const_map: Dict[object, int] = {}
        self.instrs: List[Instr] = []
        self.funcs: List[Tuple[str, int, List[str], int]] = []  # (name, nparams, params, offset placeholder)
        self.func_index: Dict[str, int] = {}
        self.cur_locals: Dict[str, int] = {}          # var name -> const id of name
        self.labels: Dict[str, int] = {}
        self.pending: List[Tuple[int, str]] = []      # (instr position, label)
        self.loop_stack: List[Tuple[List[int], List[int]]] = []  # (breaks, continues)
        self._label_n = 0

    # ------------------------------------------------------------------
    # constant pool & emission helpers
    # ------------------------------------------------------------------
    def const(self, value) -> int:
        """Return the constant-pool id for `value` (scalars only)."""
        try:
            if value in self.const_map:
                return self.const_map[value]
        except TypeError as e:  # pragma: no cover
            raise CompileError(f"unhashable constant {value!r}") from e
        cid = len(self.consts)
        if cid > 255:
            raise CompileError("constant pool exceeds 256 entries (image format limit)")
        self.consts.append(value)
        self.const_map[value] = cid
        return cid

    def emit(self, op: str, operand: int = 0) -> int:
        pos = len(self.instrs)
        self.instrs.append(Instr(op, operand))
        return pos

    def new_label(self, prefix: str) -> str:
        self._label_n += 1
        return f"{prefix}#{self._label_n}"

    def mark(self, label: str) -> None:
        self.labels[label] = len(self.instrs)

    def patch(self) -> None:
        for pos, label in self.pending:
            if label not in self.labels:
                raise CompileError(f"undefined label {label!r}")
            self.instrs[pos].operand = self.labels[label]
        self.pending = []

    def jump(self, op: str, label: str) -> None:
        self.pending.append((self.emit(op, -1), label))

    # ------------------------------------------------------------------
    # main entry
    # ------------------------------------------------------------------
    def compile_parts(self, program: Program):
        """Compile to raw (instrs, consts, funcs, entry) for the poly engine."""
        for func in program.funcs:
            if func.name in self.func_index:
                raise CompileError(f"duplicate function {func.name!r}")
            self.func_index[func.name] = len(self.funcs)
            self.funcs.append((func.name, len(func.params), list(func.params), 0))
            self.const(func.name)
        if "main" not in self.func_index:
            raise CompileError("program must define a 'main' function")
        for func in program.funcs:
            self._compile_function(func)
        return self.instrs, self.consts, self.funcs, self.func_index["main"]

    def compile(self, program: Program) -> Image:
        # 1) pre-register every function so calls can target them
        for func in program.funcs:
            if func.name in self.func_index:
                raise CompileError(f"duplicate function {func.name!r}")
            self.func_index[func.name] = len(self.funcs)
            self.funcs.append((func.name, len(func.params), list(func.params), 0))
            self.const(func.name)
        if "main" not in self.func_index:
            raise CompileError("program must define a 'main' function")

        # 2) compile each function body into the shared stream
        for func in program.funcs:
            self._compile_function(func)

        # 3) freeze addresses + pack
        entry = self.func_index["main"]
        return compile_and_pack(self.instrs, self.consts, self.funcs, entry)

    def _compile_function(self, func: FuncDef) -> None:
        self.cur_locals = {}
        for p in func.params:
            self.cur_locals[p] = self.const(p)
        self.labels = {}
        self.pending = []
        self.loop_stack = []
        start = len(self.instrs)
        for stmt in func.body:
            self.compile_stmt(stmt)
        self.patch()
        # record byte offset of this function
        self.funcs[self.func_index[func.name]] = (
            func.name, len(func.params), list(func.params), start)
        # functions must return: emit an implicit 'return none' for empty
        # bodies or fall-through that did not already end with RET.
        if len(self.instrs) == start or self.instrs[-1].op != "RET":
            self.emit("PUSH", self.const(None))
            self.emit("RET")

    # ------------------------------------------------------------------
    # statements
    # ------------------------------------------------------------------
    def compile_stmt(self, node: Node) -> None:
        if isinstance(node, Assign):
            self._assign(node)
        elif isinstance(node, Call):
            self.compile_expr(node)
            self.emit("POP")          # discard the call result
        elif isinstance(node, If):
            self._if(node)
        elif isinstance(node, For):
            self._for(node)
        elif isinstance(node, While):
            self._while(node)
        elif isinstance(node, Break):
            if not self.loop_stack:
                raise CompileError("'break' outside a loop")
            self.jump("JMP", self.loop_stack[-1][0][-1])
        elif isinstance(node, Continue):
            if not self.loop_stack:
                raise CompileError("'continue' outside a loop")
            self.jump("JMP", self.loop_stack[-1][1][-1])
        elif isinstance(node, Return):
            if node.value is None:
                self.emit("PUSH", self.const(None))
            else:
                self.compile_expr(node.value)
            self.emit("RET")
        else:
            raise CompileError(f"unsupported statement {type(node).__name__}")

    def _assign(self, node: Assign) -> None:
        if node.target not in self.cur_locals:
            self.cur_locals[node.target] = self.const(node.target)
        self.compile_expr(node.value)
        self.emit("STORE", self.cur_locals[node.target])

    def _if(self, node: If) -> None:
        else_lbl = self.new_label("else")
        end_lbl = self.new_label("ifend")
        self.compile_expr(node.cond)
        self.jump("JZ", else_lbl)
        for s in node.then:
            self.compile_stmt(s)
        self.jump("JMP", end_lbl)
        self.mark(else_lbl)
        for s in node.else_:
            self.compile_stmt(s)
        self.mark(end_lbl)

    def _for(self, node: For) -> None:
        loop_lbl = self.new_label("forloop")
        end_lbl = self.new_label("forend")
        it_slot = node.var + "\x00it"
        self.compile_expr(node.iterable)
        self.emit("ITERMK", self.const(it_slot))
        self.loop_stack.append(([end_lbl], [loop_lbl]))
        self.mark(loop_lbl)
        self.emit("ITERNX", self.const(it_slot))
        if node.var not in self.cur_locals:
            self.cur_locals[node.var] = self.const(node.var)
        self.emit("STORE", self.cur_locals[node.var])
        self.emit("LOAD", self.cur_locals[node.var])
        self.jump("JZ", end_lbl)
        for s in node.body:
            self.compile_stmt(s)
        self.jump("JMP", loop_lbl)
        self.mark(end_lbl)
        self.loop_stack.pop()

    def _while(self, node: While) -> None:
        loop_lbl = self.new_label("whileloop")
        end_lbl = self.new_label("whileend")
        self.loop_stack.append(([end_lbl], [loop_lbl]))
        self.mark(loop_lbl)
        self.compile_expr(node.cond)
        self.jump("JZ", end_lbl)
        for s in node.body:
            self.compile_stmt(s)
        self.jump("JMP", loop_lbl)
        self.mark(end_lbl)
        self.loop_stack.pop()

    # ------------------------------------------------------------------
    # expressions
    # ------------------------------------------------------------------
    def compile_expr(self, node: Node) -> None:
        if isinstance(node, Literal):
            self.emit("PUSH", self.const(node.value))
        elif isinstance(node, VarRef):
            if node.name not in self.cur_locals:
                raise CompileError(f"undefined variable {node.name!r}")
            self.emit("LOAD", self.cur_locals[node.name])
        elif isinstance(node, UnaryOp):
            self.compile_expr(node.operand)
            if node.op == "not":
                self.emit("NOT")
            elif node.op == "-":
                self.emit("NEG")
            else:
                raise CompileError(f"unknown unary operator {node.op!r}")
        elif isinstance(node, BinOp):
            if node.op not in _BINOP_OPCODE:
                raise CompileError(f"unknown binary operator {node.op!r}")
            self.compile_expr(node.left)
            self.compile_expr(node.right)
            self.emit(_BINOP_OPCODE[node.op])
        elif isinstance(node, Call):
            self._call(node)
        else:
            raise CompileError(f"unsupported expression {type(node).__name__}")

    def _call(self, node: Call) -> None:
        if node.name in self.func_index:
            self.emit("PUSHARG")
            for a in node.args:
                self.compile_expr(a)
            self.emit("CALL", self.func_index[node.name])
            return
        if node.name in self.native_index:
            self.emit("PUSHARG")
            for a in node.args:
                self.compile_expr(a)
            self.emit("NAT", self.native_index[node.name])
            return
        raise CompileError(f"unknown function/native {node.name!r}")


def compile_source(src: str, native_names: Optional[List[str]] = None) -> Image:
    """Compile JOCKY source text to an in-memory Image."""
    from .parser import parse_source
    program = parse_source(src)
    return Compiler(native_names=native_names).compile(program)