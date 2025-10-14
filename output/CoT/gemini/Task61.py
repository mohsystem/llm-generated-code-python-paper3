import xml.etree.ElementTree as ET

def get_root_element(xml_string: str) -> str:
    """
    Parses an XML string and returns the name of the root element.
    This implementation uses Python's built-in ElementTree, which is
    secure by default against DTD and external entity-related vulnerabilities.

    Args:
        xml_string: The string containing the XML document.

    Returns:
        The name of the root element, or an error message if parsing fails.
    """
    if not xml_string or not xml_string.strip():
        return "Error: XML string is null or empty."
    try:
        root = ET.fromstring(xml_string)
        return root.tag
    except ET.ParseError as e:
        return f"Error parsing XML: {e}"

def main():
    """Main function with test cases."""
    test_cases = [
        "<root><child>data</child></root>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><bookstore><book category=\"cooking\"><title lang=\"en\">Everyday Italian</title></book></bookstore>",
        "<!-- This is a comment --><project name=\"xml-parser\"><version>1.0</version></project>",
        "<note><to>Tove</to><from>Jani</from><heading>Reminder</heading></note>",
        "This is not a valid XML string."
    ]

    print("Running Python Test Cases:")
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}: \"{test_case}\"")
        print(f"Root Element: {get_root_element(test_case)}")
        print()

if __name__ == "__main__":
    main()