"""JOCKY AST node definitions.

Every node is a plain dataclass so the compiler can pattern-match on it
without any third-party dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Node:
    """Base class for every AST node."""


@dataclass
class Program(Node):
    funcs: List["FuncDef"] = field(default_factory=list)


@dataclass
class FuncDef(Node):
    name: str
    params: List[str] = field(default_factory=list)
    body: List[Node] = field(default_factory=list)


@dataclass
class Assign(Node):
    """`let name = expr` (declares+assigns) or `name = expr` (reassigns)."""
    target: str
    value: Node


@dataclass
class Call(Node):
    """Function or native call: name(args...)"""
    name: str
    args: List[Node] = field(default_factory=list)


@dataclass
class BinOp(Node):
    op: str
    left: Node
    right: Node


@dataclass
class UnaryOp(Node):
    op: str                    # 'not' | '-'
    operand: Node


@dataclass
class Literal(Node):
    value: Any


@dataclass
class VarRef(Node):
    name: str


@dataclass
class If(Node):
    cond: Node
    then: List[Node] = field(default_factory=list)
    else_: List[Node] = field(default_factory=list)


@dataclass
class For(Node):
    var: str
    iterable: Node
    body: List[Node] = field(default_factory=list)


@dataclass
class While(Node):
    cond: Node
    body: List[Node] = field(default_factory=list)


@dataclass
class Break(Node):
    pass


@dataclass
class Continue(Node):
    pass


@dataclass
class Return(Node):
    value: Optional[Node] = None