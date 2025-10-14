# Chain-of-Through Secure Implementation
# 1) Understand: Parse JSON string, extract structural representation, return root type.
# 2) Security: No eval, strict parsing, handle malformed inputs; avoid recursion blowups.
# 3) Implement: Defensive recursive-descent parser with bounds checks.
# 4) Review: Validate indices and token expectations; handle escapes.
# 5) Output: "Root=<type>; Structure=<structure>" or invalid.

from typing import Tuple, List

def extract_root_and_structure(json_str: str) -> str:
    if json_str is None:
        return "Root=invalid; Structure=invalid"
    p = _Parser(json_str)
    struct = p.parse()
    if struct is None:
        return "Root=invalid; Structure=invalid"
    root = _determine_root(struct)
    return f"Root={root}; Structure={struct}"

def _determine_root(struct: str) -> str:
    if struct.startswith("{"):
        return "object"
    if struct.startswith("["):
        return "array"
    if struct in ("string", "number", "boolean", "null"):
        return struct
    return "invalid"

class _Parser:
    MAX_DEPTH = 1000
    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.n = len(s)

    def parse(self) -> str | None:
        self._skip_ws()
        v = self._parse_value(0)
        if v is None:
            return None
        self._skip_ws()
        if self.i != self.n:
            return None
        return v

    def _skip_ws(self):
        s = self.s
        n = self.n
        i = self.i
        while i < n and s[i] in " \t\r\n":
            i += 1
        self.i = i

    def _parse_value(self, depth: int) -> str | None:
        if depth > self.MAX_DEPTH:
            return None
        self._skip_ws()
        if self.i >= self.n:
            return None
        c = self.s[self.i]
        if c == '{':
            return self._parse_object(depth + 1)
        if c == '[':
            return self._parse_array(depth + 1)
        if c == '"':
            if self._parse_string() is None:
                return None
            return "string"
        if c == '-' or c.isdigit():
            return "number" if self._parse_number() else None
        if self._match_literal("true"):
            return "boolean"
        if self._match_literal("false"):
            return "boolean"
        if self._match_literal("null"):
            return "null"
        return None

    def _match_literal(self, lit: str) -> bool:
        end = self.i + len(lit)
        if end <= self.n and self.s[self.i:end] == lit:
            self.i = end
            return True
        return False

    def _parse_object(self, depth: int) -> str | None:
        if self.i >= self.n or self.s[self.i] != '{':
            return None
        self.i += 1
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == '}':
            self.i += 1
            return "{}"
        keys: List[str] = []
        vals: List[str] = []
        while True:
            self._skip_ws()
            if self.i >= self.n or self.s[self.i] != '"':
                return None
            key = self._parse_string()
            if key is None:
                return None
            self._skip_ws()
            if self.i >= self.n or self.s[self.i] != ':':
                return None
            self.i += 1
            self._skip_ws()
            v = self._parse_value(depth)
            if v is None:
                return None
            keys.append(key)
            vals.append(v)
            self._skip_ws()
            if self.i >= self.n:
                return None
            if self.s[self.i] == ',':
                self.i += 1
                continue
            elif self.s[self.i] == '}':
                self.i += 1
                break
            else:
                return None
        parts = []
        for k, v in zip(keys, vals):
            parts.append('"' + self._escape_output(k) + '": ' + v)
        return "{" + ", ".join(parts) + "}"

    def _parse_array(self, depth: int) -> str | None:
        if self.i >= self.n or self.s[self.i] != '[':
            return None
        self.i += 1
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == ']':
            self.i += 1
            return "[]"
        elems: List[str] = []
        while True:
            v = self._parse_value(depth)
            if v is None:
                return None
            elems.append(v)
            self._skip_ws()
            if self.i >= self.n:
                return None
            if self.s[self.i] == ',':
                self.i += 1
                self._skip_ws()
                continue
            elif self.s[self.i] == ']':
                self.i += 1
                break
            else:
                return None
        uniq = []
        seen = set()
        for e in elems:
            if e not in seen:
                uniq.append(e)
                seen.add(e)
        return "[" + " | ".join(uniq) + "]"

    def _parse_string(self) -> str | None:
        if self.i >= self.n or self.s[self.i] != '"':
            return None
        self.i += 1
        out = []
        while self.i < self.n:
            c = self.s[self.i]
            self.i += 1
            if c == '"':
                return "".join(out)
            if c == '\\':
                if self.i >= self.n:
                    return None
                esc = self.s[self.i]
                self.i += 1
                if esc in '"\\/':
                    out.append(esc)
                elif esc == 'b':
                    out.append('\b')
                elif esc == 'f':
                    out.append('\f')
                elif esc == 'n':
                    out.append('\n')
                elif esc == 'r':
                    out.append('\r')
                elif esc == 't':
                    out.append('\t')
                elif esc == 'u':
                    if self.i + 4 > self.n:
                        return None
                    hexs = self.s[self.i:self.i+4]
                    if not all(ch in "0123456789abcdefABCDEF" for ch in hexs):
                        return None
                    self.i += 4
                    out.append('?')  # placeholder for unicode
                else:
                    return None
            else:
                if ord(c) <= 0x1F:
                    return None
                out.append(c)
        return None

    def _parse_number(self) -> bool:
        start = self.i
        s = self.s
        n = self.n
        if self.i < n and s[self.i] == '-':
            self.i += 1
        if self.i >= n:
            return False
        if s[self.i] == '0':
            self.i += 1
        elif s[self.i].isdigit():
            self.i += 1
            while self.i < n and s[self.i].isdigit():
                self.i += 1
        else:
            return False
        if self.i < n and s[self.i] == '.':
            self.i += 1
            if self.i >= n or not s[self.i].isdigit():
                return False
            while self.i < n and s[self.i].isdigit():
                self.i += 1
        if self.i < n and s[self.i] in 'eE':
            self.i += 1
            if self.i < n and s[self.i] in '+-':
                self.i += 1
            if self.i >= n or not s[self.i].isdigit():
                return False
            while self.i < n and s[self.i].isdigit():
                self.i += 1
        return self.i > start

    def _escape_output(self, s: str) -> str:
        out = []
        for ch in s:
            if ch in ['\\', '"']:
                out.append('\\' + ch)
            elif ord(ch) <= 0x1F:
                out.append('?')
            else:
                out.append(ch)
        return "".join(out)

if __name__ == "__main__":
    tests = [
        '{"a":1,"b":{"c":[1,2,3]},"d":[{"e":"x"},{"e":"y","f":true}]}',
        '[1,2,{"a":[null,false]}]',
        '"hello"',
        '123.45e-6',
        '{unclosed'
    ]
    for t in tests:
        print(extract_root_and_structure(t))