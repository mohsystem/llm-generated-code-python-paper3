# Step 1-5: Secure CSV parser with robust handling of quotes, commas, and newlines (RFC 4180-like)

from typing import List

def parse_csv(content: str, delimiter: str = ',') -> List[List[str]]:
    if content is None or content == "":
        return []
    records: List[List[str]] = []
    row: List[str] = []
    field_chars: List[str] = []
    in_quotes = False
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if in_quotes:
            if ch == '"':
                if i + 1 < n and content[i + 1] == '"':
                    field_chars.append('"')
                    i += 1
                else:
                    in_quotes = False
            else:
                field_chars.append(ch)
        else:
            if ch == '"':
                in_quotes = True
            elif ch == delimiter:
                row.append(''.join(field_chars))
                field_chars.clear()
            elif ch == '\n' or ch == '\r':
                row.append(''.join(field_chars))
                field_chars.clear()
                records.append(row)
                row = []
                if ch == '\r' and i + 1 < n and content[i + 1] == '\n':
                    i += 1
            else:
                field_chars.append(ch)
        i += 1

    if in_quotes or field_chars or row:
        row.append(''.join(field_chars))
        records.append(row)
    return records

def _print_parsed(title: str, data: List[List[str]]) -> None:
    print(f"=== {title} ===")
    for i, row in enumerate(data):
        formatted = " | ".join(f"[{f.replace(chr(10),'\\n').replace(chr(13),'\\r')}]" for f in row)
        print(f"Row {i}: {formatted}")
    print()

if __name__ == "__main__":
    t1 = "a,b,c\n1,2,3"
    t2 = "Name,Note\n\"Smith, John\",\"He said \"\"Hello\"\".\""
    t3 = "A,B\n\"Line1\nLine2\",X"
    t4 = "col1,col2,col3,col4\n, , ,\n,,"
    t5 = "x,y\r\n1,2\r\n3,\"4\r\n5\",6"

    _print_parsed("Test 1", parse_csv(t1))
    _print_parsed("Test 2", parse_csv(t2))
    _print_parsed("Test 3", parse_csv(t3))
    _print_parsed("Test 4", parse_csv(t4))
    _print_parsed("Test 5", parse_csv(t5))