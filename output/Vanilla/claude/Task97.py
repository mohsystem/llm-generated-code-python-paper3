
import xml.etree.ElementTree as ET
import sys

def execute_xpath(xpath_value, xml_file_name):
    try:
        tree = ET.parse(xml_file_name)
        root = tree.getroot()
        
        xpath_query = f".//*[@id='{xpath_value}']"
        elements = root.findall(xpath_query)
        
        if not elements:
            for elem in root.iter():
                if elem.get('id') == xpath_value:
                    elements.append(elem)
        
        result = []
        for element in elements:
            text_content = ''.join(element.itertext()).strip()
            result.append(f"{element.tag}: {text_content}")
        
        return '\\n'.join(result) if result else ""
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test case 1
    print("Test Case 1:")
    print(execute_xpath("1", "test1.xml"))
    print()
    
    # Test case 2
    print("Test Case 2:")
    print(execute_xpath("2", "test2.xml"))
    print()
    
    # Test case 3
    print("Test Case 3:")
    print(execute_xpath("3", "test3.xml"))
    print()
    
    # Test case 4
    print("Test Case 4:")
    print(execute_xpath("item1", "test4.xml"))
    print()
    
    # Test case 5
    print("Test Case 5:")
    print(execute_xpath("main", "test5.xml"))

if __name__ == "__main__":
    main()
