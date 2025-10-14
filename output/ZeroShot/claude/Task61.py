
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

def parse_and_get_root_element(xml_string):
    try:
        # Secure parsing - defusedxml would be even better for production
        root = ET.fromstring(xml_string)
        return root.tag
    except ParseError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test case 1: Simple XML
    test1 = '<?xml version="1.0"?><root><child>value</child></root>'
    print(f"Test 1 - Root element: {parse_and_get_root_element(test1)}")
    
    # Test case 2: XML with attributes
    test2 = '<?xml version="1.0"?><books><book id="1">Java</book></books>'
    print(f"Test 2 - Root element: {parse_and_get_root_element(test2)}")
    
    # Test case 3: Complex XML
    test3 = '<?xml version="1.0"?><company><employee><name>John</name></employee></company>'
    print(f"Test 3 - Root element: {parse_and_get_root_element(test3)}")
    
    # Test case 4: XML with namespaces
    test4 = '<?xml version="1.0"?><ns:document xmlns:ns="http://example.com"><ns:data>test</ns:data></ns:document>'
    print(f"Test 4 - Root element: {parse_and_get_root_element(test4)}")
    
    # Test case 5: Single element XML
    test5 = '<?xml version="1.0"?><message/>'
    print(f"Test 5 - Root element: {parse_and_get_root_element(test5)}")

if __name__ == "__main__":
    main()
