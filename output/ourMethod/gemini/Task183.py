import math

def largest_product(input_str: str, span: int) -> int:
    """
    Computes the largest product of a series of adjacent digits.

    :param input_str: The sequence of digits to analyze.
    :param span: The number of digits in each series.
    :return: The largest product.
    :raises ValueError: if the input is invalid.
    """
    if not isinstance(input_str, str) or not input_str.isdigit():
        raise ValueError("Input string must contain only digits.")
    if not isinstance(span, int) or span < 0:
        raise ValueError("Span cannot be negative.")
    if span > len(input_str):
        raise ValueError("Span cannot be larger than the input string length.")

    if span == 0:
        return 1

    max_product = 0
    for i in range(len(input_str) - span + 1):
        series = input_str[i:i + span]
        
        # In Python 3.8+, math.prod is a good option
        # current_product = math.prod(int(digit) for digit in series)
        
        current_product = 1
        for digit in series:
            current_product *= int(digit)
            
        if current_product > max_product:
            max_product = current_product
    
    return max_product

if __name__ == '__main__':
    # Test Case 1: Example from prompt
    input1 = "63915"
    span1 = 3
    print(f"Input: \"{input1}\", Span: {span1}, Largest Product: {largest_product(input1, span1)}") # Expected: 162

    # Test Case 2: Contains a zero
    input2 = "1027839564"
    span2 = 5
    print(f"Input: \"{input2}\", Span: {span2}, Largest Product: {largest_product(input2, span2)}") # Expected: 22680 (3*9*5*6*4)

    # Test Case 3: Span equals string length
    input3 = "73167176531330624919225119674426574742355349194934"
    span3 = 6
    print(f"Input: \"{input3[:10]}...\", Span: {span3}, Largest Product: {largest_product(input3, span3)}") # Expected: 23520

    # Test Case 4: Span is 0
    input4 = "123"
    span4 = 0
    print(f"Input: \"{input4}\", Span: {span4}, Largest Product: {largest_product(input4, span4)}") # Expected: 1

    # Test Case 5: Span is 1
    input5 = "18395"
    span5 = 1
    print(f"Input: \"{input5}\", Span: {span5}, Largest Product: {largest_product(input5, span5)}") # Expected: 9
    
    # Test Case 6: Invalid input (demonstrating exception handling)
    try:
        largest_product("123a45", 3)
    except ValueError as e:
        print(f"Caught expected exception: {e}")