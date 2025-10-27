
def write_to_file(filename, content):
    try:
        with open(filename, 'w') as file:
            file.write(content)
    except IOError as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    # Test case 1
    write_to_file("important_config", "important_config")
    
    # Test case 2
    write_to_file("test_file1.txt", "test content 1")
    
    # Test case 3
    write_to_file("test_file2.txt", "test content 2")
    
    # Test case 4
    write_to_file("config.txt", "configuration data")
    
    # Test case 5
    write_to_file("data.txt", "sample data")
    
    print("Files written successfully!")
