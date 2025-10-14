
import xml.etree.ElementTree as ET
import os
import sys
from pathlib import Path
from typing import Optional

BASE_DIRECTORY = os.getcwd()
MAX_XPATH_LENGTH = 1000
MAX_FILENAME_LENGTH = 255

def execute_xpath_query(xpath_value: str, xml_filename: str) -> str:
    if not xpath_value or len(xpath_value) > MAX_XPATH_LENGTH:
        return "Error: Invalid XPath value"
    
    if not xml_filename or len(xml_filename) > MAX_FILENAME_LENGTH:
        return "Error: Invalid file name"
    
    if not xml_filename.replace('_', '').replace('-', '').replace('.', '').isalnum():
        return "Error: Invalid file name format"
    
    if not xml_filename.endswith('.xml'):
        return "Error: Invalid file extension"
    
    try:
        base_path = Path(BASE_DIRECTORY).resolve()
        file_path = (base_path / xml_filename).resolve()
        
        if not str(file_path).startswith(str(base_path)):
            return "Error: Path traversal attempt detected"
        
        if not file_path.exists() or not file_path.is_file():
            return "Error: File does not exist or is not a regular file"
        
        sanitized_xpath = ''.join(c for c in xpath_value if c.isalnum() or c in "_-@[]='\" ")
        
        parser = ET.XMLParser()
        parser.entity = {}
        parser.parser.SetParamEntityParsing(0)
        
        tree = ET.parse(str(file_path), parser=parser)
        root = tree.getroot()
        
        xpath_query = f".//*[@id={sanitized_xpath}]"
        elements = root.findall(xpath_query)
        
        if not elements:
            return "No results found"
        
        results = []
        for elem in elements:
            text = elem.text if elem.text else ""
            results.append(text)
        
        return ", ".join(results)
        
    except ET.ParseError:
        return "Error: ParseError"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def main():
    print("Test Case 1:")
    result1 = execute_xpath_query("'test1'", "test1.xml")
    print(result1)
    
    print("\\nTest Case 2:")
    result2 = execute_xpath_query("'test2'", "test2.xml")
    print(result2)
    
    print("\\nTest Case 3:")
    result3 = execute_xpath_query("", "test.xml")
    print(result3)
    
    print("\\nTest Case 4:")
    result4 = execute_xpath_query("'test'", "../etc/passwd")
    print(result4)
    
    print("\\nTest Case 5:")
    result5 = execute_xpath_query("'test'", "nonexistent.xml")
    print(result5)

if __name__ == "__main__":
    main()
