"""JOCKY tokenizer.

Token grammar (dependency-free, both Windows & Ubuntu):
  - identifiers: [A-Za-z_][A-Za-z0-9_]*
  - integers and floats (incl. negative literals via unary '-')
  - strings: "..." or '...' with \\n \\t \\\\ \\" \\' escapes
  - operators: ( ) { } , : = + - * / % == != < > <= >= and or not
  - line comments: // to end of line
  - `;` is a statement separator (like C), newlines are skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

# Token kinds
NUMBER = "NUMBER"
STRING = "STRING"
NAME = "NAME"
OP = "OP"
EOF = "EOF"


class LexError(Exception):
    pass


@dataclass
class Token:
    kind: str
    value: object
    line: int
    col: int

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Token({self.kind}, {self.value!r}, {self.line}:{self.col})"


KEYWORDS = {
    "and", "or", "not", "true", "false", "none",
}

MULTI_OPS = ["==", "!=", "<=", ">="]
SINGLE_OPS = set("(){},:=+-*/%<>!;=")

# Semicolons are optional statement separators; the tokenizer accepts them
# so that C-style `stmt;` syntax and semicolon-free scripts both parse.


def tokenize(src: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(src)
    line = 1
    col = 1

    def bump(k=1):
        nonlocal line, col
        for _ in range(k):
            if i + _ < n and src[i + _] == "\n":
                line += 1
                col = 1
            else:
                col += 1

    while i < n:
        c = src[i]

        # whitespace
        if c in " \t\r":
            i += 1
            col += 1
            continue
        if c == "\n":
            i += 1
            line += 1
            col = 1
            continue

        # comments
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue

        # strings
        if c in ('"', "'"):
            q = c
            start_line, start_col = line, col
            i += 1
            col += 1
            buf = []
            while i < n and src[i] != q:
                ch = src[i]
                if ch == "\\":
                    if i + 1 >= n:
                        raise LexError(f"unterminated escape {start_line}:{start_col}")
                    nxt = src[i + 1]
                    esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                           '"': '"', "'": "'", "0": "\0"}
                    buf.append(esc.get(nxt, nxt))
                    i += 2
                    col += 2
                    continue
                buf.append(ch)
                i += 1
                if ch == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
            if i >= n:
                raise LexError(f"unterminated string {start_line}:{start_col}")
            i += 1  # closing quote
            col += 1
            tokens.append(Token(STRING, "".join(buf), start_line, start_col))
            continue

        # numbers
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            start_line, start_col = line, col
            j = i
            is_float = False
            while j < n and (src[j].isdigit() or src[j] == "."):
                if src[j] == ".":
                    is_float = True
                j += 1
            text = src[i:j]
            val = float(text) if is_float else int(text)
            bump(j - i)
            i = j
            tokens.append(Token(NUMBER, val, start_line, start_col))
            continue

        # identifiers / keywords
        if c.isalpha() or c == "_":
            start_line, start_col = line, col
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            word = src[i:j]
            bump(j - i)
            i = j
            tokens.append(Token(NAME,
                                word, start_line, start_col))
            continue

        # multi-char operators
        two = src[i:i + 2]
        if two in MULTI_OPS:
            tok = two
            bump(2)
            i += 2
            tokens.append(Token(OP, tok, line - (1 if tok.endswith("\n") else 0), max(col - 2, 1)))
            continue

        # single-char operators
        if c in SINGLE_OPS:
            start_line, start_col = line, col
            tokens.append(Token(OP, c, start_line, start_col))
            i += 1
            col += 1
            continue

        raise LexError(f"unexpected character {c!r} at {line}:{col}")

    tokens.append(Token(EOF, None, line, col))
    return tokens