def transpose_content(content: str) -> str:
    """
    Transposes the given content where rows are separated by newlines
    and columns by spaces.
    
    :param content: The string content to transpose.
    :return: The transposed string content.
    """
    if not content:
        return ""

    # Filter out empty lines that might result from extra newlines
    lines = [line for line in content.split('\n') if line.strip()]
    
    if not lines:
        return ""
        
    words_matrix = [line.split(' ') for line in lines]
    
    # zip(*...) is the idiomatic way to transpose a 2D list in Python
    try:
        transposed_matrix = list(zip(*words_matrix))
    except IndexError:
        return "" # Handles case of empty lines producing an empty words_matrix
    
    # Join the elements of each new row with spaces
    result_lines = [' '.join(row) for row in transposed_matrix]
    
    # Join the resulting lines with newlines
    return '\n'.join(result_lines)

if __name__ == '__main__':
    test_cases = [
        "name age\nalice 21\nryan 30",
        "a b c\nd e f\ng h i",
        "one two three four",
        "apple\nbanana\ncherry",
        ""
    ]

    for i, test in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print("Input:")
        print(test if test else "<empty>")
        print("Output:")
        result = transpose_content(test)
        print(result if result else "<empty>")
        print("--------------------")