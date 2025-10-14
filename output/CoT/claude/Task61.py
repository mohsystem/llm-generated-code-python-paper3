
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

def parse_and_get_root_element(xml_string):
    if not xml_string or not xml_string.strip():
        return "Error: Empty or null XML string"
    
    try:
        # Security: Using defusedxml would be better for production
        # For this implementation, we use standard library with precautions
        # Note: In production, use defusedxml.ElementTree instead
        
        # Parse XML string
        root = ET.fromstring(xml_string)
        
        # Return root element tag name
        return root.tag
        
    except ParseError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test case 1: Simple XML
    test1 = '<?xml version="1.0"?><root><child>data</child></root>'
    print(f"Test 1 - Root element: {parse_and_get_root_element(test1)}")
    
    # Test case 2: Complex XML
    test2 = '<?xml version="1.0" encoding="UTF-8"?><books><book id="1"><title>Java</title></book></books>'
    print(f"Test 2 - Root element: {parse_and_get_root_element(test2)}")
    
    # Test case 3: Different root element
    test3 = '<catalog><item>Product</item></catalog>'
    print(f"Test 3 - Root element: {parse_and_get_root_element(test3)}")
    
    # Test case 4: Malformed XML
    test4 = '<root><unclosed>'
    print(f"Test 4 - Root element: {parse_and_get_root_element(test4)}")
    
    # Test case 5: Empty string
    test5 = ''
    print(f"Test 5 - Root element: {parse_and_get_root_element(test5)}")

if __name__ == "__main__":
    main()
