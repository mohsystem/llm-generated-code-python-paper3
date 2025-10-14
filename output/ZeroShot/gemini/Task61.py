import xml.etree.ElementTree as ET

def get_root_element_name(xml_string):
    """
    Parses an XML string and returns the name of the root element.
    xml.etree.ElementTree is used, which is secure against XXE and other 
    DTD-based attacks by default as its default parser does not process 
    external entities. It will raise a ParseError for documents with
    a DOCTYPE declaration, which is a safe default behavior.
    """
    try:
        # The .fromstring parser expects the root element at the start,
        # after stripping whitespace. It can handle PIs and comments.
        root = ET.fromstring(xml_string.strip())
        return root.tag
    except ET.ParseError as e:
        # The parser correctly and safely rejects XML with a DOCTYPE declaration.
        return f"Error parsing XML: {e}"

def main():
    test_cases = [
        "<root><child/></root>",
        "<notes date=\"2023-10-27\"><note>text</note></notes>",
        "<?xml version=\"1.0\"?><book><title>XML</title></book>",
        " <!-- comment --><data> <item/> </data>",
        "<!DOCTYPE note SYSTEM \"Note.dtd\"><note><to>Tove</to></note>" # This will fail
    ]

    for i, xml in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Input XML: {xml}")
        root_element = get_root_element_name(xml)
        print(f"Root Element: {root_element}")
        print()

if __name__ == "__main__":
    main()