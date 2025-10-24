class Task131:
    MAX_INPUT = 4096
    MAX_FIELD_LEN = 256

    @staticmethod
    def _is_ws(c: str) -> bool:
        return c in (' ', '\n', '\r', '\t')

    @staticmethod
    def _skip_ws(s: str, i: int, end: int) -> int:
        while i < end and Task131._is_ws(s[i]):
            i += 1
        return i

    @staticmethod
    def _parse_json_string(s: str, i: int, end: int):
        if i >= end or s[i] != '"':
            return None, i, False
        i += 1
        out = []
        esc = False
        while i < end:
            c = s[i]
            if esc:
                if c == '"': out.append('"')
                elif c == '\\': out.append('\\')
                elif c == '/': out.append('/')
                elif c == 'b': out.append('\b')
                elif c == 'f': out.append('\f')
                elif c == 'n': out.append('\n')
                elif c == 'r': out.append('\r')
                elif c == 't': out.append('\t')
                elif c == 'u':
                    return None, i, False
                else:
                    return None, i, False
                esc = False
                i += 1
                continue
            else:
                if c == '\\':
                    esc = True
                    i += 1
                    continue
                elif c == '"':
                    i += 1
                    val = ''.join(out)
                    if len(val) > Task131.MAX_FIELD_LEN:
                        return None, i, False
                    return val, i, True
                else:
                    if ord(c) < 0x20:
                        return None, i, False
                    out.append(c)
                    i += 1
        return None, i, False

    @staticmethod
    def _parse_json_int(s: str, i: int, end: int):
        start = i
        neg = False
        if i < end and s[i] in '+-':
            neg = s[i] == '-'
            i += 1
        if i >= end or not s[i].isdigit():
            return 0, i, False
        val = 0
        while i < end and s[i].isdigit():
            val = val * 10 + (ord(s[i]) - 48)
            if val > 2**31 - 1:
                return 0, i, False
            i += 1
        if neg:
            val = -val
        return val, i, True

    @staticmethod
    def _json_escape(s: str) -> str:
        out = ['"']
        for ch in s:
            if ch == '"': out.append('\\"')
            elif ch == '\\': out.append('\\')
            elif ch == '\b': out.append('\\b')
            elif ch == '\f': out.append('\\f')
            elif ch == '\n': out.append('\\n')
            elif ch == '\r': out.append('\\r')
            elif ch == '\t': out.append('\\t')
            elif ord(ch) < 0x20:
                out.append('\\u%04x' % ord(ch))
            else:
                out.append(ch)
        out.append('"')
        return ''.join(out)

    @staticmethod
    def _is_valid_email(email: str) -> bool:
        if email is None:
            return False
        if len(email) < 3 or len(email) > Task131.MAX_FIELD_LEN:
            return False
        if email.count('@') != 1:
            return False
        at = email.index('@')
        if at == 0 or at == len(email) - 1:
            return False
        dot = email.find('.', at + 1)
        if dot == -1 or dot == at + 1 or dot == len(email) - 1:
            return False
        for c in email:
            if ord(c) <= 0x1F or ord(c) >= 0x7F:
                return False
            if not (c.isalnum() or c in '.-+_@'):
                return False
        return True

    @staticmethod
    def secure_deserialize(input_str: str) -> str:
        if input_str is None:
            return ""
        if len(input_str) > Task131.MAX_INPUT:
            return ""
        n = len(input_str)
        i = 0
        i = Task131._skip_ws(input_str, i, n)
        if i >= n or input_str[i] != '{':
            return ""
        i += 1
        j = n - 1
        while j >= 0 and Task131._is_ws(input_str[j]):
            j -= 1
        if j < 0 or input_str[j] != '}':
            return ""
        limit = j

        id_set = name_set = email_set = age_set = False
        id_val = age_val = 0
        name_val = email_val = None

        i = Task131._skip_ws(input_str, i, limit)
        if i < limit and input_str[i] == '}':
            return ""

        while i < limit:
            i = Task131._skip_ws(input_str, i, limit)
            key, i, ok = Task131._parse_json_string(input_str, i, limit)
            if not ok:
                return ""
            i = Task131._skip_ws(input_str, i, limit)
            if i >= limit or input_str[i] != ':':
                return ""
            i += 1
            i = Task131._skip_ws(input_str, i, limit)

            if key == "id" or key == "age":
                num, i, ok = Task131._parse_json_int(input_str, i, limit)
                if not ok:
                    return ""
                if num < 0 or num > 2**31 - 1:
                    return ""
                if key == "id":
                    if id_set: return ""
                    id_val = num; id_set = True
                else:
                    if age_set: return ""
                    age_val = num; age_set = True
            elif key == "name" or key == "email":
                val, i, ok = Task131._parse_json_string(input_str, i, limit)
                if not ok:
                    return ""
                if key == "name":
                    if name_set: return ""
                    if len(val) == 0:
                        return ""
                    name_val = val; name_set = True
                else:
                    if email_set: return ""
                    if not Task131._is_valid_email(val):
                        return ""
                    email_val = val; email_set = True
            else:
                return ""

            i = Task131._skip_ws(input_str, i, limit)
            if i < limit and input_str[i] == ',':
                i += 1
                continue
            elif i == limit:
                break
            else:
                return ""

        if i != limit:
            return ""
        if not (id_set and name_set and email_set):
            return ""

        out = []
        out.append('{')
        out.append('"id":'); out.append(str(id_val)); out.append(',')
        out.append('"name":'); out.append(Task131._json_escape(name_val)); out.append(',')
        out.append('"email":'); out.append(Task131._json_escape(email_val))
        if age_set:
            out.append(',"age":'); out.append(str(age_val))
        out.append('}')
        return ''.join(out)


if __name__ == "__main__":
    tests = [
        '{"id":123,"name":"Alice","email":"alice@example.com","age":30}',
        '{"id":1,"name":"Bob","email":"bob@example.com"}',
        '{"id":2,"name":"Mallory","email":"m@ex.com","role":"admin"}',
        '{"id":3,"name":"Eve","email":"eve@example.com","age":"30"}',
        '{"id":4,"name":"A \\"quoted\\" Name","email":"a.q@example.com","age":45}',
    ]
    for t in tests:
        res = Task131.secure_deserialize(t)
        print(res if res else "INVALID")