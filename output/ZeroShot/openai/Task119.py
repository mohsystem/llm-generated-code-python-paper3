from typing import List

def parse_csv(csv_text: str) -> List[List[str]]:
    rows: List[List[str]] = []
    if csv_text is None or len(csv_text) == 0:
        return rows

    current_row: List[str] = []
    field: List[str] = []
    in_quotes = False
    field_start = True

    i = 0
    n = len(csv_text)
    while i < n:
        ch = csv_text[i]
        if in_quotes:
            if ch == '"':
                if i + 1 < n and csv_text[i + 1] == '"':
                    field.append('"')
                    i += 1
                else:
                    in_quotes = False
            else:
                field.append(ch)
        else:
            if field_start and ch == '"':
                in_quotes = True
                field_start = False
            elif ch == ',':
                current_row.append(''.join(field))
                field = []
                field_start = True
            elif ch == '\n':
                current_row.append(''.join(field))
                field = []
                rows.append(current_row)
                current_row = []
                field_start = True
            elif ch == '\r':
                # Handle CRLF or lone CR
                if i + 1 < n and csv_text[i + 1] == '\n':
                    i += 1
                current_row.append(''.join(field))
                field = []
                rows.append(current_row)
                current_row = []
                field_start = True
            else:
                field.append(ch)
                field_start = False
        i += 1

    # Finalize
    if in_quotes:
        # Unbalanced quotes: treat as end-of-field
        pass
    if field or not field_start or current_row or (n > 0 and csv_text[-1] == ','):
        current_row.append(''.join(field))
    if current_row:
        rows.append(current_row)
    return rows

def _format_rows(rows: List[List[str]]) -> str:
    out = [f"Rows={len(rows)}"]
    for idx, r in enumerate(rows):
        safe_fields = []
        for f in r:
            safe = f.replace("\\", "\\").replace('"', '\\"')
            safe_fields.append(f'"{safe}"')
        out.append(f"Row {idx}: [" + ", ".join(safe_fields) + "]")
    return "\n".join(out)

if __name__ == "__main__":
    tests = [
        "name,age,city\nAlice,30,Seattle",
        "a,\"b,b\",c",
        "row1col1,row1col2\r\nrow2col1,\"row2\ncol2\",row2col3",
        "\"He said \"\"Hello\"\"\",42",
        "1,2,3,\n, ,\"\""
    ]
    for i, t in enumerate(tests, 1):
        parsed = parse_csv(t)
        print(f"Test {i}:")
        print(_format_rows(parsed))