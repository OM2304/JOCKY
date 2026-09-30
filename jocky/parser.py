"""JOCKY recursive-descent parser: tokens -> AST.

Grammar overview
----------------
program   := func_def*
func_def  := 'func' NAME '(' params ')' '{' stmt* '}'
params    := NAME (',' NAME)*
stmt      := 'let' NAME '=' expr ';'?
           | NAME '=' expr ';'?                        (assignment)
           | expr ';'?                                 (call statement)
           | 'if' '(' expr ')' '{' stmt* '}' ('else' '{' stmt* '}')?
           | 'for' '(' NAME 'in' expr ')' '{' stmt* '}'
           | 'while' '(' expr ')' '{' stmt* '}'
           | 'break' ';'? | 'continue' ';'? | 'return' expr? ';'?
expr      := or_expr
or_expr   := and_expr ('or' and_expr)*
and_expr  := not_expr ('and' not_expr)*
not_expr  := 'not' not_expr | cmp_expr
cmp_expr  := add_expr (('=='|'!='|'<'|'>'|'<='|'>=') add_expr)*
add_expr  := mul_expr (('+'|'-') mul_expr)*
mul_expr  := unary (('*'|'/'|'%') unary)*
unary     := '-' unary | primary
primary   := NUMBER | STRING | 'true' | 'false' | 'none'
           | NAME ('(' args ')')? | '(' expr ')'
args      := expr (',' expr)*
"""

from __future__ import annotations

from typing import List

from .ast_nodes import (
    Assign, BinOp, Break, Call, Continue, For, FuncDef, If, Literal,
    Node, Program, Return, UnaryOp, VarRef, While,
)
from .lexer import EOF, NAME, NUMBER, OP, STRING, Token, LexError


class ParseError(Exception):
    pass


class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    # ---------- helpers ----------
    def peek(self, ahead: int = 0) -> Token:
        idx = min(self.pos + ahead, len(self.tokens) - 1)
        return self.tokens[idx]

    def at(self, kind: str, value: object = None) -> bool:
        t = self.peek()
        if t.kind != kind:
            return False
        return value is None or t.value == value

    def at_name(self, name: str) -> bool:
        return self.at(NAME, name)

    def at_op(self, op: str) -> bool:
        return self.at(OP, op)

    def next(self) -> Token:
        t = self.tokens[self.pos]
        if t.kind != EOF:
            self.pos += 1
        return t

    def expect_op(self, op: str) -> Token:
        t = self.next()
        if t.kind != OP or t.value != op:
            raise ParseError(f"{t.line}:{t.col}: expected '{op}', got {t.value!r}")
        return t

    def expect_name(self) -> Token:
        t = self.next()
        if t.kind != NAME:
            raise ParseError(f"{t.line}:{t.col}: expected name, got {t.value!r}")
        return t

    def skip_sep(self) -> None:
        """Skip optional ';' separators between statements."""
        while self.at_op(";"):
            self.next()

    # ---------- program ----------
    def parse(self) -> Program:
        funcs: List[FuncDef] = []
        while not self.at(EOF):
            if not self.at_name("func"):
                raise ParseError(
                    f"{self.peek().line}:{self.peek().col}: expected 'func', "
                    f"got {self.peek().value!r}")
            funcs.append(self.parse_func())
        if not funcs:
            raise ParseError("empty program: at least one 'func' is required")
        return Program(funcs=funcs)

    def parse_func(self) -> FuncDef:
        self.next()  # 'func'
        name = self.expect_name().value
        self.expect_op("(")
        params = []
        if not self.at_op(")"):
            params.append(self.expect_name().value)
            while self.at_op(","):
                self.next()
                params.append(self.expect_name().value)
        self.expect_op(")")
        self.expect_op("{")
        body = self.parse_block_until_rbrace()
        return FuncDef(name=name, params=params, body=body)

    def parse_block_until_rbrace(self) -> List[Node]:
        stmts: List[Node] = []
        while not self.at(EOF) and not self.at_op("}"):
            stmts.append(self.parse_stmt())
            self.skip_sep()
        self.expect_op("}")
        return stmts

    # ---------- statements ----------
    def parse_stmt(self) -> Node:
        t = self.peek()

        if t.kind == NAME and t.value == "let":
            self.next()
            name = self.expect_name().value
            self.expect_op("=")
            value = self.parse_expr()
            return Assign(target=name, value=value)

        if t.kind == NAME and t.value == "if":
            return self.parse_if()

        if t.kind == NAME and t.value == "for":
            return self.parse_for()

        if t.kind == NAME and t.value == "while":
            return self.parse_while()

        if t.kind == NAME and t.value == "break":
            self.next()
            return Break()

        if t.kind == NAME and t.value == "continue":
            self.next()
            return Continue()

        if t.kind == NAME and t.value == "return":
            self.next()
            value = None
            if not (self.at_op(";") or self.at_op("}") or self.at(EOF)):
                value = self.parse_expr()
            return Return(value=value)

        # assignment: NAME '=' expr   (re-assignment to existing local)
        if t.kind == NAME and self.peek(1).kind == OP and self.peek(1).value == "=":
            name = self.next().value
            self.next()  # '='
            value = self.parse_expr()
            return Assign(target=name, value=value)

        # expression statement (typically a call)
        expr = self.parse_expr()
        return expr

    def parse_if(self) -> Node:
        self.next()  # 'if'
        self.expect_op("(")
        cond = self.parse_expr()
        self.expect_op(")")
        self.expect_op("{")
        then_branch = self.parse_block_until_rbrace()
        else_branch: List[Node] = []
        if self.at_name("else"):
            self.next()
            self.expect_op("{")
            else_branch = self.parse_block_until_rbrace()
        return If(cond=cond, then=then_branch, else_=else_branch)

    def parse_for(self) -> Node:
        self.next()  # 'for'
        self.expect_op("(")
        var = self.expect_name().value
        if not self.at_name("in"):
            raise ParseError(f"{self.peek().line}:{self.peek().col}: expected 'in'")
        self.next()
        iterable = self.parse_expr()
        self.expect_op(")")
        self.expect_op("{")
        body = self.parse_block_until_rbrace()
        return For(var=var, iterable=iterable, body=body)

    def parse_while(self) -> Node:
        self.next()  # 'while'
        self.expect_op("(")
        cond = self.parse_expr()
        self.expect_op(")")
        self.expect_op("{")
        body = self.parse_block_until_rbrace()
        return While(cond=cond, body=body)

    # ---------- expressions ----------
    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        node = self.parse_and()
        while self.at_name("or"):
            self.next()
            node = BinOp(op="or", left=node, right=self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.at_name("and"):
            self.next()
            node = BinOp(op="and", left=node, right=self.parse_not())
        return node

    def parse_not(self):
        if self.at_name("not"):
            self.next()
            return UnaryOp(op="not", operand=self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        node = self.parse_add()
        while self.peek().kind == OP and self.peek().value in ("==", "!=", "<", ">", "<=", ">="):
            op = self.next().value
            node = BinOp(op=op, left=node, right=self.parse_add())
        return node

    def parse_add(self):
        node = self.parse_mul()
        while self.peek().kind == OP and self.peek().value in ("+", "-"):
            op = self.next().value
            node = BinOp(op=op, left=node, right=self.parse_mul())
        return node

    def parse_mul(self):
        node = self.parse_unary()
        while self.peek().kind == OP and self.peek().value in ("*", "/", "%"):
            op = self.next().value
            node = BinOp(op=op, left=node, right=self.parse_unary())
        return node

    def parse_unary(self):
        if self.peek().kind == OP and self.peek().value == "-":
            self.next()
            return UnaryOp(op="-", operand=self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        t = self.peek()
        if t.kind == NUMBER:
            self.next()
            return Literal(value=t.value)
        if t.kind == STRING:
            self.next()
            return Literal(value=t.value)
        if t.kind == NAME and t.value in ("true", "false"):
            self.next()
            return Literal(value=(t.value == "true"))
        if t.kind == NAME and t.value == "none":
            self.next()
            return Literal(value=None)
        if t.kind == NAME:
            self.next()
            if self.at_op("("):
                self.next()
                args = []
                if not self.at_op(")"):
                    args.append(self.parse_expr())
                    while self.at_op(","):
                        self.next()
                        args.append(self.parse_expr())
                self.expect_op(")")
                return Call(name=t.value, args=args)
            return VarRef(name=t.value)
        if t.kind == OP and t.value == "(":
            self.next()
            node = self.parse_expr()
            self.expect_op(")")
            return node
        raise ParseError(f"{t.line}:{t.col}: unexpected token {t.value!r}")


def parse_source(src: str) -> Program:
    from .lexer import tokenize
    return Parser(tokenize(src)).parse()