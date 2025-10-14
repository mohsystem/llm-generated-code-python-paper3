
import os
import csv
from typing import List, Optional
from pathlib import Path
import re

MAX_FILE_SIZE = 10_000_000  # 10MB
MAX_FIELD_LENGTH = 10_000
MAX_FIELDS = 1000


class CSVParser:
    def __init__(self, base_dir: str) -> None:
        """Initialize CSV parser with base directory for file operations."""
        self.base_dir = str(Path(base_dir).resolve())
    
    def parse_csv_from_string(self, csv_content: str) -> List[List[str]]:
        """Parse CSV content from a string."""
        if csv_content is None:
            raise ValueError("CSV content cannot be None")
        
        if len(csv_content) > MAX_FILE_SIZE:
            raise ValueError("CSV content exceeds maximum size")
        
        result: List[List[str]] = []
        lines = csv_content.splitlines()
        
        for line in lines:
            if not line.strip():
                continue
            
            fields = self._parse_line(line)
            if len(fields) > MAX_FIELDS:
                raise ValueError("Too many fields in line")
            result.append(fields)
        
        return result
    
    def parse_csv_from_file(self, filename: str) -> List[List[str]]:
        """Parse CSV content from a file with path traversal protection."""
        if not filename or not isinstance(filename, str):
            raise ValueError("Filename cannot be empty or invalid")
        
        # Validate filename - only allow alphanumeric, dash, underscore, and .csv
        if not re.match(r'^[a-zA-Z0-9_-]+\\.csv$', filename):
            raise ValueError("Invalid filename format")
        
        file_path = Path(self.base_dir) / filename
        file_path = file_path.resolve()
        
        # Prevent path traversal
        if not str(file_path).startswith(self.base_dir):
            raise SecurityError("Path traversal attempt detected")
        
        # Check if file exists and is a regular file
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError("File not found or not a regular file")
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError("File size exceeds maximum allowed size")
        
        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return self.parse_csv_from_string(content)
    
    def _parse_line(self, line: str) -> List[str]:
        """Parse a single CSV line handling quoted fields."""
        if line is None:
            return []
        
        fields: List[str] = []
        current_field: List[str] = []
        in_quotes = False
        i = 0
        
        while i < len(line):
            c = line[i]
            
            if c == '"':
                if in_quotes and i + 1 < len(line) and line[i + 1] == '"':
                    current_field.append('"')
                    i += 1
                else:
                    in_quotes = not in_quotes
            elif c == ',' and not in_quotes:
                field = ''.join(current_field)
                if len(field) > MAX_FIELD_LENGTH:
                    raise ValueError("Field exceeds maximum length")
                fields.append(field)
                current_field = []
            else:
                current_field.append(c)
            
            i += 1
        
        field = ''.join(current_field)
        if len(field) > MAX_FIELD_LENGTH:
            raise ValueError("Field exceeds maximum length")
        fields.append(field)
        
        return fields


def main() -> None:
    """Test the CSV parser with various test cases."""
    try:
        import tempfile
        
        # Test case 1: Simple CSV parsing from string
        print("Test 1: Simple CSV")
        csv1 = "name,age,city\\nAlice,30,New York\\nBob,25,Los Angeles"
        parser = CSVParser(tempfile.gettempdir())
        result1 = parser.parse_csv_from_string(csv1)
        for row in result1:
            print(row)
        
        # Test case 2: CSV with quoted fields
        print("\\nTest 2: CSV with quotes")
        csv2 = 'name,description\\n"John Doe","He said, ""Hello"""\\nJane,Simple text'
        result2 = parser.parse_csv_from_string(csv2)
        for row in result2:
            print(row)
        
        # Test case 3: Empty fields
        print("\\nTest 3: Empty fields")
        csv3 = "a,b,c\\n1,,3\\n,2,\\n,,"
        result3 = parser.parse_csv_from_string(csv3)
        for row in result3:
            print(row)
        
        # Test case 4: Single column
        print("\\nTest 4: Single column")
        csv4 = "header\\nvalue1\\nvalue2\\nvalue3"
        result4 = parser.parse_csv_from_string(csv4)
        for row in result4:
            print(row)
        
        # Test case 5: Special characters
        print("\\nTest 5: Special characters")
        csv5 = 'id,text\\n1,"Line1\\nLine2"\\n2,Tab\\there'
        result5 = parser.parse_csv_from_string(csv5)
        for row in result5:
            print(row)
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
