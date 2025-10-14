import sys
import os

def execute_xpath_like(xml_file_path: str, id_value: str) -> str:
    try:
        with open(xml_file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return ""
    result_parts = []
    pos = 0
    while True:
        start = content.find("<tag", pos)
        if start == -1:
            break
        gt = content.find(">", start)
        if gt == -1:
            break
        self_closing = gt > start and content[gt - 1] == '/'
        attrs = content[start + 4:gt]
        attr_val = extract_attr_value(attrs, "id")
        if attr_val is not None and attr_val == id_value:
            if self_closing:
                result_parts.append(content[start:gt + 1])
            else:
                end_idx = find_matching_end(content, gt + 1)
                if end_idx != -1:
                    result_parts.append(content[start:end_idx])
        pos = start + 1
    return "\n".join(result_parts)

def find_matching_end(s: str, from_idx: int) -> int:
    depth = 1
    search = from_idx
    while depth > 0:
        next_open = s.find("<tag", search)
        next_close = s.find("</tag>", search)
        if next_close == -1:
            return -1
        if next_open != -1 and next_open < next_close:
            gt2 = s.find(">", next_open)
            if gt2 == -1:
                return -1
            self_closing = gt2 > next_open and s[gt2 - 1] == '/'
            if not self_closing:
                depth += 1
            search = gt2 + 1
        else:
            depth -= 1
            search = next_close + len("</tag>")
    return search

def extract_attr_value(attrs: str, name: str):
    i = index_of_word(attrs, name, 0)
    while i != -1:
        j = i + len(name)
        while j < len(attrs) and attrs[j].isspace():
            j += 1
        if j < len(attrs) and attrs[j] == '=':
            j += 1
            while j < len(attrs) and attrs[j].isspace():
                j += 1
            if j < len(attrs):
                q = attrs[j]
                if q in ("'", '"'):
                    k = attrs.find(q, j + 1)
                    if k != -1:
                        return attrs[j + 1:k]
                else:
                    k = j
                    while k < len(attrs) and not attrs[k].isspace():
                        k += 1
                    return attrs[j:k]
        i = index_of_word(attrs, name, i + 1)
    return None

def index_of_word(s: str, w: str, start: int) -> int:
    i = start - 1
    while True:
        i = s.find(w, i + 1)
        if i == -1:
            return -1
        left_ok = (i == 0) or (not s[i - 1].isalnum())
        end = i + len(w)
        right_ok = (end >= len(s)) or (not s[end].isalnum())
        if left_ok and right_ok:
            return i

def write_sample_file(path: str):
    xml = (
        "<root>\n"
        "  <tag id=\"1\">Content one</tag>\n"
        "  <tag id=\"2\">\n"
        "     Two\n"
        "     <child>Alpha</child>\n"
        "  </tag>\n"
        "  <tag id=\"3\"/>\n"
        "  <other id=\"1\">Not a tag</other>\n"
        "  <tag id=\"nested\">\n"
        "     <tag id=\"inner\">Inner content</tag>\n"
        "  </tag>\n"
        "  <tag id=\"spaces\">  spaced  </tag>\n"
        "</root>\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)

def main():
    if len(sys.argv) >= 3:
        id_val = sys.argv[1]
        xml_path = sys.argv[2]
        xpath = f"/tag[@id='{id_val}']"
        out = execute_xpath_like(xml_path, id_val)
        print(out)
        return
    sample_path = "sample_task97.xml"
    write_sample_file(sample_path)
    tests = ["1", "2", "3", "missing", "nested"]
    for t in tests:
        xpath = f"/tag[@id='{t}']"
        res = execute_xpath_like(sample_path, t)
        print(f"XPath: {xpath}")
        print(res)
        print("-----")

if __name__ == "__main__":
    main()