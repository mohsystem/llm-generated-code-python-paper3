
import xml.etree.ElementTree as ET

def get_root_element(xml_string):
    try:
        root = ET.fromstring(xml_string)
        return root.tag
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test case 1: Simple XML
    xml1 = "<?xml version=\"1.0\"?><root><child>value</child></root>"
    print(f"Test 1 - Root element: {get_root_element(xml1)}")
    
    # Test case 2: XML with attributes
    xml2 = "<?xml version=\"1.0\"?><book id=\"1\"><title>Java Programming</title></book>"
    print(f"Test 2 - Root element: {get_root_element(xml2)}")
    
    # Test case 3: XML with nested elements
    xml3 = "<?xml version=\"1.0\"?><catalog><product><name>Item1</name></product></catalog>"
    print(f"Test 3 - Root element: {get_root_element(xml3)}")
    
    # Test case 4: XML with different root
    xml4 = "<?xml version=\"1.0\"?><students><student><name>John</name></student></students>"
    print(f"Test 4 - Root element: {get_root_element(xml4)}")
    
    # Test case 5: Simple root without declaration
    xml5 = "<data><item>test</item></data>"
    print(f"Test 5 - Root element: {get_root_element(xml5)}")
