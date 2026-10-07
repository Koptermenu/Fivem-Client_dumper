"""A real Lua 5.4 lexer: strings, comments, names, symbols.

Reading these files as latin-1 keeps a 1:1 char/byte mapping, so offsets stay
byte-exact and multiset comparisons are byte-faithful even when a decompiled
file contains non-UTF-8 bytes. Nothing here is a regex over source text.
"""

KEYWORDS = frozenset(
    """and break do else elseif end false for function goto if in local nil not
    or repeat return then true until while""".split()
)

_NAME_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_NAME_CHAR = _NAME_START | set("0123456789")
_DIGITS = set("0123456789")
_HEX = set("0123456789abcdefABCDEF")
_WS = set(" \t\r\n\v\f")



BANNER_MARKERS = (
    "AI CLEANUP",
    "Decompiled Lua",
    "SHX_LABEL_XX",
    "no visible label",
    "decompiler comments",
    "Fix indentation",
    "Rename SHX",
    "Replace goto/label",
    "Move ::",
)

SPACE = "space"
LINE_COMMENT = "linecomment"
BLOCK_COMMENT = "blockcomment"
STRING = "string"
NUMBER = "number"
NAME = "name"
SYMBOL = "symbol"
END = "end"


_OPERATORS = (
    "...", "..", "::", "==", "~=", "<=", ">=", "//", "<<", ">>",
    "+", "-", "*", "/", "%", "^", "#", "&", "~", "|", "<", ">", "=",
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
)


class Token:
    __slots__ = ("kind", "begin", "end", "text", "value", "closed")

    def __init__(self, kind, begin, end, text, value=None, closed=True):
        self.kind = kind
        self.begin = begin
        self.end = end
        self.text = text
        self.value = value
        self.closed = closed

    def __repr__(self):
        return "Token(%s,%r)" % (self.kind, self.text[:40])


def is_banner(text):
    return any(m in text for m in BANNER_MARKERS)


class LuaSyntaxError(Exception):
    pass


def _long_bracket_level(src, i):
    """If src[i:] opens a long bracket, return its level, else None."""
    if i >= len(src) or src[i] != "[":
        return None
    j = i + 1
    lvl = 0
    while j < len(src) and src[j] == "=":
        lvl += 1
        j += 1
    if j < len(src) and src[j] == "[":
        return lvl
    return None


def _long_bracket_close(src, i, lvl):
    needle = "]" + ("=" * lvl) + "]"
    k = src.find(needle, i)
    return k


def _decode_quoted(body):
    out = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            out.append("\\")
            break
        e = body[i]
        i += 1
        simple = {
            "a": "\x07", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
            "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'",
        }
        if e in simple:
            out.append(simple[e])
            continue
        if e == "\n":
            out.append("\n")
            continue
        if e == "x":
            h = body[i:i + 2]
            if len(h) == 2 and all(ch in _HEX for ch in h):
                out.append(chr(int(h, 16)))
                i += 2
                continue
            out.append("x")
            continue
        if e == "z":
            while i < n and body[i] in _WS:
                i += 1
            continue
        if e == "u":
            if body[i:i + 1] == "{":
                j = body.find("}", i)
                hexpart = body[i + 1:j] if j != -1 else ""
                if hexpart and all(ch in _HEX for ch in hexpart):
                    out.append(chr(int(hexpart, 16)))
                    i = j + 1
                    continue
            out.append("u")
            continue
        if e in _DIGITS:
            j = i
            while j < n and j < i + 2 and body[j] in _DIGITS:
                j += 1
            out.append(chr(int(body[i - 1:j], 10) & 0xFF))
            i = j
            continue
        out.append(e)
    return "".join(out)


def tokenize(src):
    """Tokenize Lua source. Never raises; unterminated constructs get closed=False."""
    toks = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in _WS:
            j = i
            while j < n and src[j] in _WS:
                j += 1
            toks.append(Token(SPACE, i, j, src[i:j]))
            i = j
            continue
        if c == "-" and src.startswith("--", i):
            lvl = _long_bracket_level(src, i + 2)
            if lvl is not None:
                close = _long_bracket_close(src, i + 2, lvl)
                body_start = i + 3 + lvl
                if close == -1:
                    toks.append(Token(BLOCK_COMMENT, i, n, src[i:], src[body_start:], False))
                    i = n
                    continue
                body_end = close
                body = src[body_start:body_end]
                if body[:1] == "\n":
                    body = body[1:]
                elif body[:2] == "\r\n":
                    body = body[2:]
                toks.append(Token(BLOCK_COMMENT, i, close + 2 + lvl, src[i:close + 2 + lvl], body))
                i = close + 2 + lvl
                continue
            j = src.find("\n", i)
            if j == -1:
                j = n
            body = src[i + 2:j]
            toks.append(Token(LINE_COMMENT, i, j, src[i:j], body))
            i = j
            continue
        if c in "\"'":
            quote = c
            j = i + 1
            buf = []
            closed = True
            while j < n:
                ch = src[j]
                if ch == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if ch == quote:
                    j += 1
                    break
                if ch == "\n":
                    closed = False
                    break
                buf.append(ch)
                j += 1
            else:
                closed = False
            raw = src[i + 1:j - 1] if closed else src[i + 1:j]
            toks.append(Token(STRING, i, j, src[i:j], _decode_quoted(raw), closed))
            i = j
            continue
        if c == "[" and _long_bracket_level(src, i) is not None:
            lvl = _long_bracket_level(src, i)
            body_start = i + 2 + lvl
            close = _long_bracket_close(src, body_start, lvl)
            if close == -1:
                toks.append(Token(STRING, i, n, src[i:], src[body_start:], False))
                i = n
                continue
            body = src[body_start:close]
            if body[:1] == "\n":
                body = body[1:]
            elif body[:2] == "\r\n":
                body = body[2:]
            toks.append(Token(STRING, i, close + 2 + lvl, src[i:close + 2 + lvl], body))
            i = close + 2 + lvl
            continue
        if c in _NAME_START:
            j = i + 1
            while j < n and src[j] in _NAME_CHAR:
                j += 1
            toks.append(Token(NAME, i, j, src[i:j]))
            i = j
            continue
        if c in _DIGITS or (c == "." and i + 1 < n and src[i + 1] in _DIGITS):
            j = i
            seen_dot = False
            seen_exp = False
            while j < n:
                ch = src[j]
                if ch in _DIGITS or ch in _HEX or ch in "xX":
                    j += 1
                elif ch == "." and not seen_dot and not seen_exp:
                    seen_dot = True
                    j += 1
                elif ch in "pP" or (ch in "eE" and not seen_exp):
                    seen_exp = True
                    j += 1
                    if j < n and src[j] in "+-":
                        j += 1
                elif ch in _NAME_CHAR:
                    j += 1
                else:
                    break
            toks.append(Token(NUMBER, i, j, src[i:j]))
            i = j
            continue
        for op in _OPERATORS:
            if src.startswith(op, i):
                toks.append(Token(SYMBOL, i, i + len(op), op))
                i += len(op)
                break
        else:
            i += 1
    toks.append(Token(END, n, n, ""))
    return toks


def read_lua(path):
    with open(path, "rb") as fh:
        return fh.read().decode("latin-1")


def strings(src):
    """Multiset-friendly list of (decoded_value, closed) for every string literal."""
    return [(t.value, t.closed) for t in tokenize(src) if t.kind == STRING]


def comments(src):
    """List of (kind, stripped_text, raw_text) for every comment."""
    out = []
    for t in tokenize(src):
        if t.kind in (LINE_COMMENT, BLOCK_COMMENT):
            out.append((t.kind, (t.value or "").strip(), t.text))
    return out


def line_count(src):
    if not src:
        return 0
    n = src.count("\n")
    if not src.endswith("\n"):
        n += 1
    return n


def _code_tokens(src):
    return [t for t in tokenize(src) if t.kind != SPACE]


def _lhs_indices(code, i):
    """Indices of the assignment targets left of the '=' at code[i].

    Stops at the previous '=' so the right hand side of the statement above is
    never mistaken for a target: in `a = f` newline `b = g`, `f` is a read.
    """
    out = []
    j = i - 1
    while j >= 0:
        if not (code[j].kind == NAME and code[j].text not in KEYWORDS):
            break
        out.append(j)
        j -= 1
        while j >= 0:
            if (code[j].kind == SYMBOL and code[j].text == "." and j >= 1
                    and code[j - 1].kind == NAME):
                j -= 2
                continue
            if code[j].kind == SYMBOL and code[j].text == "]":
                depth = 0
                while j >= 0:
                    d = code[j]
                    if d.kind == SYMBOL and d.text == "]":
                        depth += 1
                    elif d.kind == SYMBOL and d.text == "[":
                        depth -= 1
                        if depth == 0:
                            j -= 1
                            break
                    j -= 1
                continue
            break
        if j >= 0 and code[j].kind == SYMBOL and code[j].text == ",":
            j -= 1
            continue
        break
    return out


def _write_map(code):
    """(indices that receive a value, names that receive a value).

    Over-approximates deliberately: anything that could be a binding site is
    counted, so a missing write is reported as a missing write rather than
    silently treated as a read.
    """
    n = len(code)
    indices = set()
    names = set()

    def mark(i):
        t = code[i]
        if t.kind == NAME and t.text not in KEYWORDS:
            indices.add(i)
            names.add(t.text)

    for i, t in enumerate(code):
        if t.kind == SYMBOL and t.text == "=":
            for k in _lhs_indices(code, i):
                mark(k)

    for i, t in enumerate(code):
        if t.kind != NAME:
            continue
        if t.text == "local":
            j = i + 1
            if j < n and code[j].kind == NAME and code[j].text == "function":
                j += 1
            while j < n:
                mark(j)
                nxt = code[j + 1] if j + 1 < n else None
                if nxt is not None and nxt.kind == SYMBOL and nxt.text in (",", ";"):
                    j += 2
                    continue
                break
        elif t.text == "for":
            j = i + 1
            while j < n:
                if code[j].kind != NAME or code[j].text in KEYWORDS:
                    break
                mark(j)
                nxt = code[j + 1] if j + 1 < n else None
                if nxt is not None and nxt.kind == SYMBOL and nxt.text == ",":
                    j += 2
                    continue
                break
        elif t.text == "function":
            j = i + 1
            while j < n:
                if code[j].kind == SYMBOL and code[j].text == "(":
                    depth = 0
                    while j < n:
                        c = code[j]
                        if c.kind == SYMBOL and c.text in "([{":
                            depth += 1
                        elif c.kind == SYMBOL and c.text in ")]}":
                            depth -= 1
                            if depth == 0:
                                break
                        else:
                            mark(j)
                        j += 1
                    break
                if code[j].kind == NAME and code[j].text not in KEYWORDS:
                    mark(j)
                    j += 1
                    continue
                if code[j].kind == SYMBOL and code[j].text in (";",) :
                    break
                j += 1
    return indices, names


def names_written(src):
    """Every name that can receive a value anywhere in the file."""
    return _write_map(_code_tokens(src))[1]


def names_assigned(src):
    """Names that actually receive a value from an assignment.

    A bare `local a, b` binds them to nil and is deliberately not counted:
    a name that is read but never assigned is undefined, and that is the
    shape a deleted live store leaves behind.
    """
    code = _code_tokens(src)
    out = set()
    for i, t in enumerate(code):
        if t.kind == SYMBOL and t.text == "=":
            for k in _lhs_indices(code, i):
                c = code[k]
                if c.kind == NAME and c.text not in KEYWORDS:
                    out.add(c.text)
    return out


def names_read(src):
    """Names used as values: excludes field names, keywords and write targets."""
    code = _code_tokens(src)
    write_idx, _names = _write_map(code)
    reads = set()
    for i, t in enumerate(code):
        if t.kind != NAME or t.text in KEYWORDS or i in write_idx:
            continue
        prev = code[i - 1] if i else None
        if prev is not None and prev.kind == SYMBOL and prev.text in (".", ":"):
            continue
        reads.add(t.text)
    return reads


def names_declared(src):
    """Names bound by a `local` declaration, including `local function`."""
    code = _code_tokens(src)
    n = len(code)
    out = set()
    for i, t in enumerate(code):
        if t.kind != NAME or t.text != "local":
            continue
        j = i + 1
        if j < n and code[j].kind == NAME and code[j].text == "function":
            j += 1
        while j < n and code[j].kind == NAME and code[j].text not in KEYWORDS:
            out.add(code[j].text)
            j += 1
            nxt = code[j] if j < n else None
            if nxt is not None and nxt.kind == SYMBOL and nxt.text in (",", ";"):
                j += 1
                continue
            break
    return out