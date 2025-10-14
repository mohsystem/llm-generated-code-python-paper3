from typing import Optional
import xml.etree.ElementTree as ET

def get_root_element(xml: str) -> str:
    if not isinstance(xml, str):
        return ""
    MAX_LEN = 1_000_000
    s = xml.strip()
    if not s or len(s) > MAX_LEN:
        return ""
    try:
        root = ET.fromstring(s)
        tag = root.tag or ""
        # If namespace in Clark notation {uri}local, return local name to avoid exposing URIs
        if tag.startswith("{"):
            end = tag.find("}")
            if end != -1:
                tag = tag[end+1:]
        return tag
    except ET.ParseError:
        return ""

if __name__ == "__main__":
    tests = [
        "<root><child/></root>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a attr=\"1\">text</a>",
        "  <!--comment-->\n<store><item/></store>",
        "<ns:books xmlns:ns=\"urn:x\"><ns:book/></ns:books>",
        ""
    ]
    for t in tests:
        print(get_root_element(t))