import sys
import os

def query_by_id(xml_path: str, id_value: str):
    if xml_path is None or id_value is None:
        raise ValueError("xml_path and id_value are required")
    xml_path = os.path.abspath(xml_path)
    if not os.path.isfile(xml_path):
        raise FileNotFoundError(f"File not found: {xml_path}")

    with open(xml_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "<!DOCTYPE" in content:
        raise SecurityError("DOCTYPE is disallowed for security reasons.")

    # Minimal, safe parsing tailored for /tag[@id=value] where 'tag' is the document element.
    # We avoid external entity expansion by not using parsers that fetch external resources.
    def extract_root_tag(xml_text):
        i = 0
        n = len(xml_text)
        # Skip BOM
        if xml_text.startswith("\ufeff"):
            i += 1
        # Skip XML declaration
        if xml_text[i:i+5].lower() == "<?xml":
            end_decl = xml_text.find("?>", i+5)
            if end_decl == -1:
                return None, -1, -1
            i = end_decl + 2
        # Skip whitespace
        while i < n and xml_text[i].isspace():
            i += 1
        if i >= n or xml_text[i] != '<':
            return None, -1, -1
        # Read tag name
        j = i + 1
        while j < n and (xml_text[j].isalnum() or xml_text[j] in ['_', ':', '-']):
            j += 1
        tag_name = xml_text[i+1:j]
        return tag_name, i, j

    def parse_id_in_start_tag(xml_text, start_tag_start, after_name_idx):
        n = len(xml_text)
        k = after_name_idx
        id_val = None
        in_quote = None
        attr_name = []
        attr_val = []
        state = "seek_attr"
        while k < n:
            ch = xml_text[k]
            if state == "seek_attr":
                if ch == '>':
                    break
                if ch == '/' and k+1 < n and xml_text[k+1] == '>':
                    k += 2
                    break
                if ch.isspace():
                    k += 1
                    continue
                # start attr name
                attr_name = [ch]
                state = "attr_name"
                k += 1
            elif state == "attr_name":
                if ch.isspace() or ch == '=' or ch == '>' or (ch == '/' and k+1 < n and xml_text[k+1] == '>'):
                    name = ''.join(attr_name).strip()
                    # expect '='
                    while k < n and xml_text[k].isspace():
                        k += 1
                    if k < n and xml_text[k] == '=':
                        k += 1
                        while k < n and xml_text[k].isspace():
                            k += 1
                        if k < n and xml_text[k] in ['"', "'"]:
                            in_quote = xml_text[k]
                            k += 1
                            attr_val = []
                            state = "attr_val"
                        else:
                            # malformed, skip
                            state = "seek_attr"
                    else:
                        state = "seek_attr"
                else:
                    attr_name.append(ch)
                    k += 1
            elif state == "attr_val":
                if ch == in_quote:
                    value = ''.join(attr_val)
                    if name == "id":
                        # unescape minimal entities
                        value = value.replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                        id_val = value
                    state = "seek_attr"
                    k += 1
                else:
                    attr_val.append(ch)
                    k += 1
            else:
                k += 1
        return id_val

    tag_name, start_idx, after_name = extract_root_tag(content)
    if tag_name != "tag":
        return []

    root_id = parse_id_in_start_tag(content, start_idx, after_name)
    if root_id != id_value:
        return []

    # Extract full root element string
    # Determine if self-closing
    end_start = content.find('>', after_name)
    if end_start == -1:
        return []
    start_tag_text = content[start_idx:end_start+1]
    if start_tag_text.rstrip().endswith("/>"):
        element = start_tag_text
    else:
        close_tag = "</tag>"
        end_idx = content.find(close_tag, end_start+1)
        if end_idx == -1:
            return []
        element = content[start_idx:end_idx+len(close_tag)]

    return [element]

class SecurityError(Exception):
    pass

def _write(path, txt):
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        res = query_by_id(sys.argv[1], sys.argv[2])
        for r in res:
            print(r)
    else:
        files = [
            "sample97_1.xml",
            "sample97_2.xml",
            "sample97_3.xml",
            "sample97_4.xml",
            "sample97_5.xml"
        ]
        contents = [
            '<tag id="1">Alpha</tag>',
            '<tag id="abc">Bravo</tag>',
            '<tag id="he said &quot;hi&quot; and \'yo\'">Charlie</tag>',
            '<tag id="no-match">Delta</tag>',
            '<tag id="5"><child>Echo</child></tag>'
        ]
        for f, c in zip(files, contents):
            _write(f, c)

        print("Test1:", query_by_id(files[0], "1"))
        print("Test2:", query_by_id(files[1], "abc"))
        print("Test3:", query_by_id(files[2], 'he said "hi" and \'yo\''))
        print("Test4:", query_by_id(files[3], "x"))
        print("Test5:", query_by_id(files[4], "5"))