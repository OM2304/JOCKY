"""JOCKY -- a next-gen forensic scripting language framework (SIH26148).

Pipeline:  source (.jck) -> lexer -> parser (AST) -> compiler (bytecode)
          -> polymorphic image (.jcx) -> VM (in-memory execution)

The framework ships four example scripts (examples/) and a remote
management layer (agents/) so a single operator can push analysis
tasks to many hosts at once, with traffic relayed over trusted cloud
infrastructure.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .bytecode import Image, Instr, OP_NAMES, OP_WIDTHS
from .compiler import Compiler, compile_source
from .parser import parse_source
from .vm import VM
from .stdlib import NATIVES, NATIVE_NAMES, NATIVE_FUNCS
from . import crypto, poly

__all__ = [
    "__version__",
    "Image", "Instr", "OP_NAMES", "OP_WIDTHS",
    "Compiler", "compile_source", "parse_source",
    "VM", "NATIVES", "NATIVE_NAMES", "NATIVE_FUNCS",
    "crypto", "poly",
]