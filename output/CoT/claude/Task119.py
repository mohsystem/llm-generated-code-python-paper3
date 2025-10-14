
import csv
import os
import re
from typing import List

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_ROWS = 100000


def parse_csv(file_path: str) -> List[List[str]]:
    """Parse a CSV file and return its contents as a list of lists."""
    
    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be null or empty")
    
    # Security: Validate file path to prevent directory traversal
    try:
        canonical_path = os.path.realpath(file_path)
        current_dir = os.path.realpath(".")
        if not canonical_path.startswith(current_dir):
            raise SecurityError("Access denied: Invalid file path")
    except Exception as e:
        raise SecurityError(f"Cannot validate file path: {str(e)}")
    
    # Security: Check file exists and is a file
    if not os.path.isfile(file_path):
        raise ValueError("File does not exist or is not a file")
    
    # Security: Check file size
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ValueError("File size exceeds maximum allowed size")
    
    # Security: Validate file extension
    if not file_path.lower().endswith('.csv'):
        raise ValueError("Only CSV files are allowed")
    
    records = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as csvfile:
            csv_reader = csv.reader(csvfile)
            row_count = 0
            
            for row in csv_reader:
                # Security: Limit number of rows
                row_count += 1
                if row_count > MAX_ROWS:
                    raise ValueError("File exceeds maximum row limit")
                
                # Security: Sanitize each field
                sanitized_row = [sanitize_field(field) for field in row]
                records.append(sanitized_row)
                
    except IOError as e:
        raise RuntimeError(f"Error reading CSV file: {str(e)}")
    
    return records


def sanitize_field(field: str) -> str:
    """Sanitize a CSV field to prevent injection attacks."""
    
    if field is None:
        return ""
    
    field = field.strip()
    
    # Security: Prevent formula injection in CSV
    if field and field[0] in ('=', '+', '-', '@'):
        field = "'" + field
    
    return field


def write_csv(file_path: str, data: List[List[str]]) -> None:
    """Write data to a CSV file."""
    
    if not file_path or not file_path.strip():
        raise ValueError("File path cannot be null or empty")
    
    if not data:
        raise ValueError("Data cannot be null or empty")
    
    # Security: Validate file path
    try:
        canonical_path = os.path.realpath(file_path)
        current_dir = os.path.realpath(".")
        if not canonical_path.startswith(current_dir):
            raise SecurityError("Access denied: Invalid file path")
    except Exception as e:
        raise SecurityError(f"Cannot validate file path: {str(e)}")
    
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            for row in data:
                csv_writer.writerow(row)
                
    except IOError as e:
        raise RuntimeError(f"Error writing CSV file: {str(e)}")


class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass


def main():
    """Main function with test cases."""
    
    try:
        # Test case 1: Create and parse simple CSV
        test_data1 = [
            ["Name", "Age", "City"],
            ["John Doe", "30", "New York"],
            ["Jane Smith", "25", "Los Angeles"]
        ]
        write_csv("test1.csv", test_data1)
        result1 = parse_csv("test1.csv")
        print("Test 1 - Simple CSV:")
        for record in result1:
            print(record)
        
        # Test case 2: CSV with quoted fields
        test_data2 = [
            ["Product", "Description", "Price"],
            ["Book", "A great book, highly recommended", "19.99"],
            ["Pen", "Blue ink pen", "2.50"]
        ]
        write_csv("test2.csv", test_data2)
        result2 = parse_csv("test2.csv")
        print("\\nTest 2 - CSV with commas:")
        for record in result2:
            print(record)
        
        # Test case 3: CSV with special characters
        test_data3 = [
            ["ID", "Email", "Status"],
            ["001", "user@example.com", "Active"],
            ["002", "admin@test.org", "Inactive"]
        ]
        write_csv("test3.csv", test_data3)
        result3 = parse_csv("test3.csv")
        print("\\nTest 3 - CSV with special characters:")
        for record in result3:
            print(record)
        
        # Test case 4: CSV with empty fields
        test_data4 = [
            ["Field1", "Field2", "Field3"],
            ["Value1", "", "Value3"],
            ["", "Value2", ""]
        ]
        write_csv("test4.csv", test_data4)
        result4 = parse_csv("test4.csv")
        print("\\nTest 4 - CSV with empty fields:")
        for record in result4:
            print(record)
        
        # Test case 5: CSV with numeric data
        test_data5 = [
            ["Year", "Revenue", "Profit"],
            ["2021", "1000000", "250000"],
            ["2022", "1500000", "400000"]
        ]
        write_csv("test5.csv", test_data5)
        result5 = parse_csv("test5.csv")
        print("\\nTest 5 - CSV with numeric data:")
        for record in result5:
            print(record)
        
        # Cleanup test files
        for i in range(1, 6):
            try:
                os.remove(f"test{i}.csv")
            except:
                pass
                
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
