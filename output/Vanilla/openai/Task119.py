from typing import List

class Task119:
    @staticmethod
    def parse_csv(text: str) -> List[List[str]]:
        rows: List[List[str]] = []
        if text is None:
            return rows
        field = []
        row: List[str] = []
        in_quotes = False
        i = 0
        n = len(text)
        any_char = False
        ended_on_newline = False

        while i < n:
            c = text[i]
            any_char = True
            if in_quotes:
                if c == '"':
                    if i + 1 < n and text[i + 1] == '"':
                        field.append('"')
                        i += 2
                    else:
                        in_quotes = False
                        i += 1
                else:
                    field.append(c)
                    i += 1
                ended_on_newline = False
            else:
                if c == '"':
                    in_quotes = True
                    i += 1
                    ended_on_newline = False
                elif c == ',':
                    row.append(''.join(field))
                    field = []
                    i += 1
                    ended_on_newline = False
                elif c == '\r' or c == '\n':
                    row.append(''.join(field))
                    field = []
                    rows.append(row)
                    row = []
                    if c == '\r' and i + 1 < n and text[i + 1] == '\n':
                        i += 2
                    else:
                        i += 1
                    ended_on_newline = True
                else:
                    field.append(c)
                    i += 1
                    ended_on_newline = False

        if in_quotes or field or row or (any_char and not ended_on_newline):
            row.append(''.join(field))
            rows.append(row)
        return rows

    @staticmethod
    def to_csv(rows: List[List[str]]) -> str:
        if rows is None:
            return ""
        out_parts: List[str] = []
        for r_idx, row in enumerate(rows):
            fields_out: List[str] = []
            for f in row:
                need_quotes = any(ch in ('"', ',', '\n', '\r') for ch in f)
                if need_quotes:
                    escaped = f.replace('"', '""')
                    fields_out.append(f'"{escaped}"')
                else:
                    fields_out.append(f)
            out_parts.append(','.join(fields_out))
        return '\n'.join(out_parts)

def _print_rows(title: str, rows: List[List[str]]) -> None:
    print(title)
    for i, r in enumerate(rows):
        print(f"Row {i} [" + " | ".join(r) + "]")

if __name__ == "__main__":
    tests = [
        "a,b,c\n1,2,3",
        "name,quote\nJohn,\"Hello, world\"",
        "id,notes\n1,\"Line1\nLine2\"\n2,\"A\"",
        "text\n\"He said \"\"Hi\"\"\"",
        "a,b,c\r\n1,,3\r\n,2,\r\n",
    ]
    for idx, csv in enumerate(tests, 1):
        print(f"==== Test {idx} ====")
        parsed = Task119.parse_csv(csv)
        _print_rows("Parsed:", parsed)
        serialized = Task119.to_csv(parsed)
        print("Serialized:")
        print(serialized)
        print()