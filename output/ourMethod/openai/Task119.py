from typing import List, Sequence, Tuple

def parse_csv(text: str, delimiter: str = ",") -> List[List[str]]:
    if text is None:
        raise ValueError("text must not be None")
    if not isinstance(delimiter, str) or len(delimiter) != 1:
        raise ValueError("delimiter must be a single-character string")
    rows: List[List[str]] = []
    row: List[str] = []
    field_chars: List[str] = []
    in_quotes = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_quotes:
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    field_chars.append('"')
                    i += 1
                else:
                    in_quotes = False
            else:
                field_chars.append(c)
        else:
            if c == '"':
                in_quotes = True
            elif c == delimiter:
                row.append("".join(field_chars))
                field_chars.clear()
            elif c == "\n" or c == "\r":
                # Handle CRLF
                if c == "\r" and i + 1 < n and text[i + 1] == "\n":
                    i += 1
                row.append("".join(field_chars))
                field_chars.clear()
                rows.append(row)
                row = []
            else:
                field_chars.append(c)
        i += 1
    # finalize
    row.append("".join(field_chars))
    if not (len(rows) == 0 and len(row) == 1 and row[0] == ""):
        rows.append(row)
    return rows

def to_csv(rows: Sequence[Sequence[str]], delimiter: str = ",") -> str:
    if rows is None:
        raise ValueError("rows must not be None")
    if not isinstance(delimiter, str) or len(delimiter) != 1:
        raise ValueError("delimiter must be a single-character string")
    out_lines: List[str] = []
    for r in rows:
        fields: List[str] = []
        for f in r:
            field = "" if f is None else str(f)
            must_quote = any(ch in field for ch in (delimiter, '"', "\n", "\r"))
            if must_quote:
                field = '"' + field.replace('"', '""') + '"'
            fields.append(field)
        out_lines.append(delimiter.join(fields))
    return "\n".join(out_lines)

def select_columns(rows: Sequence[Sequence[str]], indices: Sequence[int]) -> List[List[str]]:
    if rows is None or indices is None:
        raise ValueError("rows/indices must not be None")
    for idx in indices:
        if not isinstance(idx, int) or idx < 0:
            raise ValueError("indices must be non-negative integers")
    out: List[List[str]] = []
    for r in rows:
        new_row = []
        for idx in indices:
            new_row.append(r[idx] if idx < len(r) else "")
        out.append(new_row)
    return out

def sum_column(rows: Sequence[Sequence[str]], col_index: int) -> float:
    if rows is None:
        raise ValueError("rows must not be None")
    if not isinstance(col_index, int) or col_index < 0:
        raise ValueError("col_index must be a non-negative integer")
    total = 0.0
    for r in rows:
        if col_index < len(r):
            val = (r[col_index] or "").strip()
            if val:
                try:
                    total += float(val)
                except ValueError:
                    pass
    return total

def _print_rows(rows: List[List[str]]) -> None:
    print(f"Rows: {len(rows)}")
    for r in rows:
        print(r)

if __name__ == "__main__":
    # Test 1: Simple CSV
    csv1 = "a,b\nc,d"
    rows1 = parse_csv(csv1, ",")
    print("Test1 parsed:")
    _print_rows(rows1)
    print("Test1 serialized:")
    print(to_csv(rows1, ","))
    print()

    # Test 2: Quoted with comma
    csv2 = "name,age\n\"Doe, John\",42\n\"Smith, Jane\",35"
    rows2 = parse_csv(csv2, ",")
    print("Test2 parsed:")
    _print_rows(rows2)
    print("Sum age:", sum_column(rows2[1:], 1))  # exclude header
    print()

    # Test 3: Newlines in quoted fields and escaped quotes
    csv3 = "id,notes\n1,\"Line1\nLine2\"\n2,\"He said \"\"Hello\"\"\""
    rows3 = parse_csv(csv3, ",")
    print("Test3 parsed:")
    _print_rows(rows3)
    print("Test3 serialized:")
    print(to_csv(rows3, ","))
    print()

    # Test 4: Empty fields and trailing delimiters
    csv4 = "a,,c\n,d,\n,,"
    rows4 = parse_csv(csv4, ",")
    print("Test4 parsed:")
    _print_rows(rows4)
    sel4 = select_columns(rows4, [0, 2])
    print("Test4 select col 0 and 2:")
    _print_rows(sel4)
    print()

    # Test 5: Custom delimiter and CRLF
    csv5 = "x;y\r\n1;2\r\n\"3;4\";5"
    rows5 = parse_csv(csv5, ";")
    print("Test5 parsed:")
    _print_rows(rows5)
    print("Test5 serialized with ';':")
    print(to_csv(rows5, ";"))