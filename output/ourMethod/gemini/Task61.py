import xml.etree.ElementTree as ET
from typing import List

def get_root_element_name(xml_string: str) -> str:
    """
    Parses an XML string and returns the name of the root element.
    The default xml.etree.ElementTree parser is secure against DTD-based
    attacks like XXE as it does not process external entities by default.

    Args:
        xml_string: The XML string to parse.

    Returns:
        The name of the root element, or an empty string if parsing fails or
        the input is invalid.
    """
    if not isinstance(xml_string, str) or not xml_string.strip():
        return ""
    
    try:
        root = ET.fromstring(xml_string)
        return root.tag
    except ET.ParseError:
        # In a production environment, this error should be logged.
        return ""

def main() -> None:
    """Main function to run test cases."""
    test_cases: List[str] = [
        # 1. Simple valid XML
        "<root><child>data</child></root>",
        # 2. XML with attributes and a different root name
        "<document id='123'><item>value</item></document>",
        # 3. Malformed XML (unclosed tag)
        "<notes><note>text</notes>",
        # 4. Empty string input
        "",
        # 5. XML with a DOCTYPE declaration (should be safely rejected)
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
    ]

    for i, xml in enumerate(test_cases, 1):
        root_element = get_root_element_name(xml)
        print(f"Test Case {i}:")
        print(f'Input XML: "{xml}"')
        print(f'Root Element: "{root_element}"\n')

if __name__ == "__main__":
    main()