class Node:
    def __init__(self, name: str):
        self.name = name
        self.children = []

def get_root_element_name(xml: str) -> str:
    if xml is None:
        return ""
    root_name, _ = _parse_xml_root(xml)
    return root_name or ""

def _parse_xml_root(xml: str):
    a = xml
    n = len(a)
    i = 0
    stack = []
    root_name = None
    root_node = None

    def starts_with(pos: int, s: str) -> bool:
        return a.startswith(s, pos)

    def index_of_seq2(pos: int, x: str, y: str) -> int:
        p = pos
        while p + 1 < n:
            if a[p] == x and a[p + 1] == y:
                return p + 1
            p += 1
        return -1

    def index_of_seq3(pos: int, x: str, y: str, z: str) -> int:
        p = pos
        while p + 2 < n:
            if a[p] == x and a[p + 1] == y and a[p + 2] == z:
                return p + 2
            p += 1
        return -1

    def skip_spaces(pos: int) -> int:
        p = pos
        while p < n and a[p] in ' \t\r\n':
            p += 1
        return p

    def is_name_char(c: str) -> bool:
        return c.isalnum() or c in "_-:."

    def skip_declaration(pos: int) -> int:
        depth = 0
        p = pos
        while p < n:
            c = a[p]
            if c == '[':
                depth += 1
            elif c == ']':
                if depth > 0:
                    depth -= 1
            elif c == '>' and depth == 0:
                return p
            p += 1
        return -1

    def skip_to_tag_end(pos: int) -> int:
        quote = None
        p = pos
        while p < n:
            c = a[p]
            if quote is not None:
                if c == quote:
                    quote = None
                p += 1
                continue
            else:
                if c in ("'", '"'):
                    quote = c
                elif c == '>':
                    return p
                p += 1
        return -1

    while i < n:
        lt = a.find('<', i)
        if lt == -1:
            break
        i = lt
        if i + 1 >= n:
            break

        if starts_with(i, "<?"):
            j = index_of_seq2(i + 2, '?', '>')
            if j == -1:
                break
            i = j + 1
            continue

        if starts_with(i, "<!--"):
            j = index_of_seq3(i + 4, '-', '-', '>')
            if j == -1:
                break
            i = j + 1
            continue

        if starts_with(i, "<![CDATA["):
            j = index_of_seq3(i + 9, ']', ']', '>')
            if j == -1:
                break
            i = j + 1
            continue

        if starts_with(i, "<!"):
            j = skip_declaration(i + 2)
            if j == -1:
                break
            i = j + 1
            continue

        if a[i + 1] == '/':
            j = i + 2
            j = skip_spaces(j)
            start = j
            while j < n and is_name_char(a[j]):
                j += 1
            j = skip_to_tag_end(j)
            if j == -1:
                break
            if stack:
                stack.pop()
            i = j + 1
            continue

        j = i + 1
        j = skip_spaces(j)
        start = j
        while j < n and is_name_char(a[j]):
            j += 1
        if j == start:
            i += 1
            continue
        name = a[start:j]
        node = Node(name)
        if not stack:
            root_name = name
            root_node = node
        else:
            stack[-1].children.append(node)

        self_close = False
        k = j
        quote = None
        while k < n:
            c = a[k]
            if quote is not None:
                if c == quote:
                    quote = None
                k += 1
                continue
            else:
                if c in ("'", '"'):
                    quote = c
                    k += 1
                    continue
                if c == '/':
                    if k + 1 < n and a[k + 1] == '>':
                        self_close = True
                        k += 2
                        break
                if c == '>':
                    k += 1
                    break
                k += 1
        if not self_close:
            stack.append(node)
        i = k

    return root_name, root_node

if __name__ == "__main__":
    tests = [
        "<root><child/></root>",
        "<?xml version='1.0'?><!-- comment --><a id='1'><b></b><c/></a>",
        "  \n <root>text<inner>more</inner></root> ",
        "<x><y></x>",
        "<!DOCTYPE note SYSTEM 'Note.dtd'><note><![CDATA[<notatag>]]><to>T</to></note>"
    ]
    for t in tests:
        print(get_root_element_name(t))