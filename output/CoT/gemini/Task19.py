def spin_words(sentence):
    """
    Reverses words in a string that have five or more letters.

    :param sentence: The input string of one or more words.
    :return: The string with long words reversed.
    """
    words = sentence.split(' ')
    spun_words = []
    for word in words:
        if len(word) >= 5:
            spun_words.append(word[::-1])
        else:
            spun_words.append(word)
    return ' '.join(spun_words)

if __name__ == '__main__':
    test_cases = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "Welcome",
        "Just kidding there is still one more"
    ]

    expected_results = [
        "Hey wollef sroirraw",
        "This is a test",
        "This is rehtona test",
        "emocleW",
        "Just gniddik ereht is llits one more"
    ]

    for i, test in enumerate(test_cases):
        result = spin_words(test)
        print(f"Test Case {i + 1}:")
        print(f"Input:    \"{test}\"")
        print(f"Output:   \"{result}\"")
        print(f"Expected: \"{expected_results[i]}\"")
        print(f"Result: {'Passed' if result == expected_results[i] else 'Failed'}")
        print()