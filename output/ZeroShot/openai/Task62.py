class Task62:
    @staticmethod
    def identify_root(json_str: str) -> str:
        if json_str is None:
            return "invalid"
        MAX_LEN = 1_000_000
        if len(json_str) > MAX_LEN:
            return "invalid"
        p = _Parser(json_str)
        t = p.parse_root()
        return t if t is not None else "invalid"

class _Parser:
    MAX_DEPTH = 512

    def __init__(self, s: str):
        self.s = s
        self.len = len(s)
        self.pos = 0
        self.depth = 0

    def parse_root(self):
        self._skip_ws()
        if self.pos >= self.len:
            return None
        t = self._parse_value()
        if t is None:
            return None
        self._skip_ws()
        return t if self.pos == self.len else None

    def _skip_ws(self):
        while self.pos < self.len and self.s[self.pos] in ' \t\r\n':
            self.pos += 1

    def _parse_value(self):
        self._skip_ws()
        if self.pos >= self.len:
            return None
        c = self.s[self.pos]
        if c == '{':
            return "object" if self._parse_object() else None
        if c == '[':
            return "array" if self._parse_array() else None
        if c == '"':
            return "string" if self._parse_string() else None
        if c == '-' or c.isdigit():
            return "number" if self._parse_number() else None
        if self.s.startswith("true", self.pos):
            self.pos += 4
            return "boolean"
        if self.s.startswith("false", self.pos):
            self.pos += 5
            return "boolean"
        if self.s.startswith("null", self.pos):
            self.pos += 4
            return "null"
        return None

    def _parse_object(self):
        if self.depth >= self.MAX_DEPTH:
            return False
        if self.pos >= self.len or self.s[self.pos] != '{':
            return False
        self.depth += 1
        self.pos += 1
        self._skip_ws()
        if self.pos < self.len and self.s[self.pos] == '}':
            self.pos += 1
            self.depth -= 1
            return True
        while True:
            self._skip_ws()
            if not self._parse_string():
                self.depth -= 1
                return False
            self._skip_ws()
            if self.pos >= self.len or self.s[self.pos] != ':':
                self.depth -= 1
                return False
            self.pos += 1
            if self._parse_value() is None:
                self.depth -= 1
                return False
            self._skip_ws()
            if self.pos < self.len and self.s[self.pos] == ',':
                self.pos += 1
                continue
            elif self.pos < self.len and self.s[self.pos] == '}':
                self.pos += 1
                self.depth -= 1
                return True
            else:
                self.depth -= 1
                return False

    def _parse_array(self):
        if self.depth >= self.MAX_DEPTH:
            return False
        if self.pos >= self.len or self.s[self.pos] != '[':
            return False
        self.depth += 1
        self.pos += 1
        self._skip_ws()
        if self.pos < self.len and self.s[self.pos] == ']':
            self.pos += 1
            self.depth -= 1
            return True
        while True:
            if self._parse_value() is None:
                self.depth -= 1
                return False
            self._skip_ws()
            if self.pos < self.len and self.s[self.pos] == ',':
                self.pos += 1
                continue
            elif self.pos < self.len and self.s[self.pos] == ']':
                self.pos += 1
                self.depth -= 1
                return True
            else:
                self.depth -= 1
                return False

    def _parse_string(self):
        if self.pos >= self.len or self.s[self.pos] != '"':
            return False
        self.pos += 1
        while self.pos < self.len:
            c = self.s[self.pos]
            self.pos += 1
            if c == '"':
                return True
            if c == '\\':
                if self.pos >= self.len:
                    return False
                e = self.s[self.pos]
                self.pos += 1
                if e in '"\\/bfnrt':
                    continue
                if e == 'u':
                    for _ in range(4):
                        if self.pos >= self.len:
                            return False
                        h = self.s[self.pos]
                        if not (h.isdigit() or 'a' <= h <= 'f' or 'A' <= h <= 'F'):
                            return False
                        self.pos += 1
                else:
                    return False
            else:
                if ord(c) < 0x20:
                    return False
        return False

    def _parse_number(self):
        start = self.pos
        if self.pos < self.len and self.s[self.pos] == '-':
            self.pos += 1
        if self.pos >= self.len:
            return False
        if self.s[self.pos] == '0':
            self.pos += 1
        elif self.s[self.pos].isdigit() and self.s[self.pos] != '0':
            while self.pos < self.len and self.s[self.pos].isdigit():
                self.pos += 1
        else:
            return False
        if self.pos < self.len and self.s[self.pos] == '.':
            self.pos += 1
            if self.pos >= self.len or not self.s[self.pos].isdigit():
                return False
            while self.pos < self.len and self.s[self.pos].isdigit():
                self.pos += 1
        if self.pos < self.len and self.s[self.pos] in 'eE':
            self.pos += 1
            if self.pos < self.len and self.s[self.pos] in '+-':
                self.pos += 1
            if self.pos >= self.len or not self.s[self.pos].isdigit():
                return False
            while self.pos < self.len and self.s[self.pos].isdigit():
                self.pos += 1
        return self.pos > start

if __name__ == "__main__":
    tests = [
        '{"a":1,"b":[true,false,null]}',
        '[1,2,3]',
        '"hello"',
        '123.45e-6',
        '{unquoted: 1}',
    ]
    for t in tests:
        print(Task62.identify_root(t))