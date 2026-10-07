"""Shared Lua-side facts about a file: which names are synthetic registers, which
identifiers are already in use, and where a register token actually appears.

Kept separate from both the harness and the applier so the two cannot drift: the applier's
safety argument depends on the register list being derived once, the same way, before any
model output is seen.
"""

import io
import re

SYNTH_RE = re.compile(r"\b(SHX\d*_\d+|text\d+|num\d+|table\d+|L\d+_\d+)\b")

KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if",
    "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
}

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
STR_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|\[(=*)\[.*?\]\1\]", re.S)
COMMENT_RE = re.compile(r"--\[\[.*?\]\]|--[^\n]*", re.S)


def read(path):
    with io.open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def strip_noise(src):
    """Blanks strings and comments, keeping every byte offset intact.

    Register counting and identifier extraction must not see a register name that only
    appears inside a string or a comment: renaming those would change data, not code.
    """
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))

    return COMMENT_RE.sub(blank, STR_RE.sub(blank, src))


def registers(src):
    """Every synthetic register occurrence, in source order, duplicates included."""
    return SYNTH_RE.findall(strip_noise(src))


def register_set(src):
    return set(registers(src))


def identifiers(src):
    """Every identifier used in code, strings and comments excluded."""
    return set(IDENT_RE.findall(strip_noise(src)))


def read_lua(path, synth_only):
    src = read(path)
    regs = registers(src)
    if synth_only and not regs:
        return None
    return src, regs, register_set(src), identifiers(src)