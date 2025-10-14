from typing import Tuple

class ParseError(Exception):
    pass

def identify_root_element(json_text: str) -> str:
    if json_text is None:
        return "INVALID"
    if len(json_text.encode("utf-8")) > 1_000_000:
        return "INVALID"
    p = _Parser(json_text)
    try:
        p.skip_ws()
        node_type = p.parse_value()
        p.skip_ws()
        if not p.at_end():
            return "INVALID"
        return {
            "OBJECT": "object",
            "ARRAY": "array",
            "STRING": "string",
            "NUMBER": "number",
            "BOOLEAN": "boolean",
            "NULL": "null",
        }[node_type]
    except ParseError:
        return "INVALID"

class _Parser:
    def __init__(self, s: str):
        self.s = s
        self.n = len(s)
        self.i = 0

    def at_end(self) -> bool:
        return self.i >= self.n

    def skip_ws(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t\r\n":
            self.i += 1

    def parse_value(self) -> str:
        if self.i >= self.n:
            raise ParseError("Unexpected end")
        c = self.s[self.i]
        if c == '{':
            self.parse_object()
            return "OBJECT"
        if c == '[':
            self.parse_array()
            return "ARRAY"
        if c == '"':
            self.parse_string()
            return "STRING"
        if c == 't':
            self.expect_literal("true")
            return "BOOLEAN"
        if c == 'f':
            self.expect_literal("false")
            return "BOOLEAN"
        if c == 'n':
            self.expect_literal("null")
            return "NULL"
        if c == '-' or c.isdigit():
            self.parse_number()
            return "NUMBER"
        raise ParseError("Invalid value")

    def parse_object(self) -> None:
        self.expect_char('{')
        self.skip_ws()
        if self.peek_char('}'):
            self.i += 1
            return
        while True:
            self.skip_ws()
            self.parse_string()  # key
            self.skip_ws()
            self.expect_char(':')
            self.skip_ws()
            self.parse_value()
            self.skip_ws()
            if self.peek_char('}'):
                self.i += 1
                return
            self.expect_char(',')

    def parse_array(self) -> None:
        self.expect_char('[')
        self.skip_ws()
        if self.peek_char(']'):
            self.i += 1
            return
        while True:
            self.skip_ws()
            self.parse_value()
            self.skip_ws()
            if self.peek_char(']'):
                self.i += 1
                return
            self.expect_char(',')

    def parse_string(self) -> None:
        self.expect_char('"')
        while self.i < self.n:
            c = self.s[self.i]
            self.i += 1
            if c == '"':
                return
            if c == '\\':
                if self.i >= self.n:
                    raise ParseError("Unterminated escape")
                e = self.s[self.i]
                self.i += 1
                if e in ['"', '\\', '/', 'b', 'f', 'n', 'r', 't']:
                    continue
                if e == 'u':
                    for _ in range(4):
                        if self.i >= self.n:
                            raise ParseError("Bad unicode escape")
                        h = self.s[self.i]
                        self.i += 1
                        if not (h.isdigit() or 'a' <= h <= 'f' or 'A' <= h <= 'F'):
                            raise ParseError("Bad unicode hex")
                else:
                    raise ParseError("Invalid escape")
            else:
                if ord(c) < 0x20:
                    raise ParseError("Control in string")
        raise ParseError("Unterminated string")

    def parse_number(self) -> None:
        start = self.i
        if self.peek_char('-'):
            self.i += 1
        if self.i >= self.n:
            raise ParseError("Bad number")
        if self.peek_char('0'):
            self.i += 1
        else:
            if not (self.i < self.n and self.s[self.i].isdigit() and self.s[self.i] != '0'):
                raise ParseError("Bad int")
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
        if self.peek_char('.'):
            self.i += 1
            if self.i >= self.n or not self.s[self.i].isdigit():
                raise ParseError("Bad fraction")
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
        if self.i < self.n and self.s[self.i] in 'eE':
            self.i += 1
            if self.i < self.n and self.s[self.i] in '+-':
                self.i += 1
            if self.i >= self.n or not self.s[self.i].isdigit():
                raise ParseError("Bad exponent")
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
        if self.i <= start:
            raise ParseError("Empty number")

    def expect_literal(self, lit: str) -> None:
        end = self.i + len(lit)
        if end > self.n or self.s[self.i:end] != lit:
            raise ParseError(f"Expected {lit}")
        self.i = end

    def expect_char(self, ch: str) -> None:
        if self.i >= self.n or self.s[self.i] != ch:
            raise ParseError(f"Expected '{ch}'")
        self.i += 1

    def peek_char(self, ch: str) -> bool:
        return self.i < self.n and self.s[self.i] == ch

if __name__ == "__main__":
    tests = [
        '{"a":1,"b":[true,false,null],"c":{"d":"x"}}',
        '[1,2,3, {"k": ["v", 2]}]',
        '"hello world"',
        '-12.3e-5',
        'true',
    ]
    for t in tests:
        print(identify_root_element(t))