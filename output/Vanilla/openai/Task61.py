import xml.etree.ElementTree as ET

def get_root_element(xml_str: str):
    if xml_str is None:
        return None
    try:
        root = ET.fromstring(xml_str)
        return root.tag
    except Exception:
        return None

if __name__ == "__main__":
    tests = [
        "<root></root>",
        "<?xml version=\"1.0\"?><a><b/></a>",
        "  \n<!-- comment -->\n<ns:catalog attr='1'><item/></ns:catalog>",
        "<!DOCTYPE note [<!ELEMENT note (to)>]><note><to>Tove</to></note>",
        "<unclosed"
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {get_root_element(t)}")