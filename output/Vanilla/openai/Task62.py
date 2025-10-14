def get_json_root_type(json_str: str) -> str:
    if json_str is None:
        return "invalid"
    i = 0
    n = len(json_str)
    while i < n and json_str[i].isspace():
        i += 1
    if i >= n:
        return "invalid"
    c = json_str[i]
    if c == '{':
        return "object"
    if c == '[':
        return "array"
    if c == '"':
        return "string"
    if c in ('t', 'f'):
        return "boolean"
    if c == 'n':
        return "null"
    if c == '-' or c.isdigit():
        return "number"
    return "invalid"


if __name__ == "__main__":
    tests = [
        '{"name":"Alice","age":30}',
        '[{"id":1},{"id":2}]',
        '"sample"',
        '-42.0e10',
        'true',
    ]
    for t in tests:
        print(get_json_root_type(t))