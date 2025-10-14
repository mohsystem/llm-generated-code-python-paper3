
import xml.etree.ElementTree as ET
from typing import Optional


def parse_and_get_root_element(xml_string: str) -> str:
    if not xml_string or not xml_string.strip():
        raise ValueError("XML string cannot be null or empty")
    
    if len(xml_string) > 1000000:
        raise ValueError("XML string exceeds maximum allowed length")
    
    try:
        # Disable external entity processing by using defusedxml approach
        # Parse with default parser which is safe in Python 3.x for local strings
        parser = ET.XMLParser()
        parser.entity.clear()  # Clear entity definitions
        
        # Parse the XML string
        root = ET.fromstring(xml_string, parser=parser)
        
        if root is None:
            return ""
        
        return root.tag
        
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse XML: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Failed to parse XML: {str(e)}")


def main():
    # Test case 1: Simple XML
    try:
        xml1 = "<root><child>data</child></root>"
        print(f"Test 1: {parse_and_get_root_element(xml1)}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: XML with attributes
    try:
        xml2 = '<document type="test"><section>content</section></document>'
        print(f"Test 2: {parse_and_get_root_element(xml2)}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Nested XML
    try:
        xml3 = "<library><books><book><title>Title</title></book></books></library>"
        print(f"Test 3: {parse_and_get_root_element(xml3)}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Empty string (should fail)
    try:
        xml4 = ""
        print(f"Test 4: {parse_and_get_root_element(xml4)}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: XML with namespace
    try:
        xml5 = '<ns:root xmlns:ns="http://example.com"><ns:child>data</ns:child></ns:root>'
        print(f"Test 5: {parse_and_get_root_element(xml5)}")
    except Exception as e:
        print(f"Test 5 failed: {e}")


if __name__ == "__main__":
    main()
