import os

def transpose_file(file_path):
    """
    Transposes the content of a text file.
    
    :param file_path: The path to the input text file.
    """
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            return

        # Split lines into words and create a matrix, filtering out empty lines
        matrix = [line.strip().split() for line in lines if line.strip()]
        
        if not matrix:
            return

        # Transpose the matrix using zip
        transposed = zip(*matrix)
        
        # Print the transposed matrix
        for row in transposed:
            print(' '.join(row))

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    test_contents = [
        # Test Case 1: Example from prompt
        "name age\nalice 21\nryan 30",
        # Test Case 2: Single row
        "a b c d",
        # Test Case 3: Single column
        "a\nb\nc",
        # Test Case 4: 4x4 matrix
        "1 2 3 4\n5 6 7 8\n9 10 11 12\n13 14 15 16",
        # Test Case 5: 3x3 with strings
        "first middle last\njohn f kennedy\nmartin luther king"
    ]

    file_name = "file.txt"
    for i, content in enumerate(test_contents):
        print(f"--- Test Case {i + 1} ---")
        print("Input:")
        print(content)
        print("\nOutput:")
        
        with open(file_name, 'w') as f:
            f.write(content)
        
        transpose_file(file_name)
        print()

    # Clean up the created file
    if os.path.exists(file_name):
        os.remove(file_name)

if __name__ == "__main__":
    main()