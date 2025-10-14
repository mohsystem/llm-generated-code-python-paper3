def spin_words(sentence):
    words = sentence.split(' ')
    spun_words = [word[::-1] if len(word) >= 5 else word for word in words]
    return ' '.join(spun_words)

if __name__ == '__main__':
    # Test Case 1
    input1 = "Hey fellow warriors"
    print(f'Input: "{input1}"')
    print(f'Output: "{spin_words(input1)}"\n')  # Expected: "Hey wollef sroirraw"

    # Test Case 2
    input2 = "This is a test"
    print(f'Input: "{input2}"')
    print(f'Output: "{spin_words(input2)}"\n')  # Expected: "This is a test"

    # Test Case 3
    input3 = "This is another test"
    print(f'Input: "{input3}"')
    print(f'Output: "{spin_words(input3)}"\n')  # Expected: "This is rehtona test"

    # Test Case 4
    input4 = "Welcome"
    print(f'Input: "{input4}"')
    print(f'Output: "{spin_words(input4)}"\n')  # Expected: "emocleW"

    # Test Case 5
    input5 = "Just kidding there is still one more"
    print(f'Input: "{input5}"')
    print(f'Output: "{spin_words(input5)}"\n')  # Expected: "Just gniddik ereht is llits one more"