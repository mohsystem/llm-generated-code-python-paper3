import xml.etree.ElementTree as ET

def get_root_element(xml_string):
    """
    Parses an XML string and returns the tag of the root element.
    
    :param xml_string: The string containing the XML document.
    :return: The name of the root element, or an error message if parsing fails.
    """
    try:
        # fromstring parses XML from a string directly to an Element
        root = ET.fromstring(xml_string)
        return root.tag
    except ET.ParseError as e:
        return f"Error parsing XML: {e}"

def main():
    """
    Main function with test cases.
    """
    test_cases = [
        "<root><child/></root>",
        "<bookstore category=\"COOKING\"><book/></bookstore>",
        "<?xml version=\"1.0\"?><note><to>Tove</to></note>",
        "  <data>  </data>  ",
        "<employees><employee><id>1</id></employee></employees>"
    ]
    
    print("Python Test Cases:")
    for xml in test_cases:
        print(f"Input: {xml}")
        print(f"Root Element: {get_root_element(xml)}")
        print("---")

if __name__ == "__main__":
    main()