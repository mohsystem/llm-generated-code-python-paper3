def get_root_element_name(xml: str) -> str:
    if xml is None:
        return ""
    n = len(xml)
    i = 0

    # Skip BOM
    if i < n and xml[i] == '\ufeff':
        i += 1

    def starts_with_at(s: str, idx: int, pat: str) -> bool:
        return s.startswith(pat, idx)

    while i < n:
        # Skip whitespace
        while i < n and xml[i] in (' ', '\t', '\r', '\n'):
            i += 1
        if i >= n:
            break

        # Processing Instruction
        if starts_with_at(xml, i, "<?"):
            end = xml.find("?>", i + 2)
            if end == -1:
                return ""
            i = end + 2
            continue

        # Comment
        if starts_with_at(xml, i, "<!--"):
            end = xml.find("-->", i + 4)
            if end == -1:
                return ""
            i = end + 3
            continue

        # CDATA (unlikely in prolog), skip
        if starts_with_at(xml, i, "<![CDATA["):
            end = xml.find("]]>", i + 9)
            if end == -1:
                return ""
            i = end + 3
            continue

        # DOCTYPE or other declaration
        if starts_with_at(xml, i, "<!"):
            i += 2  # after "<!"
            depth = 0
            in_quote = False
            quote_ch = ''
            while i < n:
                ch = xml[i]
                if in_quote:
                    if ch == quote_ch:
                        in_quote = False
                else:
                    if ch == '"' or ch == "'":
                        in_quote = True
                        quote_ch = ch
                    elif ch == '[':
                        depth += 1
                    elif ch == ']':
                        if depth > 0:
                            depth -= 1
                    elif ch == '>' and depth == 0:
                        i += 1
                        break
                i += 1
            continue

        # Start tag
        if xml[i] == '<':
            if i + 1 < n and xml[i + 1] == '/':
                return ""
            j = i + 1
            while j < n and xml[j] not in (' ', '\t', '\r', '\n', '/', '>'):
                j += 1
            if j == i + 1:
                return ""
            return xml[i + 1:j]

        # Other characters
        i += 1

    return ""


if __name__ == "__main__":
    tests = [
        "<root></root>",
        "<?xml version=\"1.0\"?><root attr='1'><child/></root>",
        "<!-- comment --><!DOCTYPE note [<!ELEMENT note ANY>]><note><to>T</to></note>",
        "<x:Root xmlns:x='urn:x'><x:child/></x:Root>",
        "\ufeff  <?pi test?><root/>",
    ]
    for t in tests:
        print(get_root_element_name(t))