def to_jaden_case(quote):
    """
    Converts a string to Jaden Case.
    """
    if not quote:
        return ""
    # The capitalize() method is better than title() for this,
    # as it correctly handles contractions (e.g., "aren't").
    return " ".join(word.capitalize() for word in quote.split())

if __name__ == '__main__':
    test_cases = [
        "How can mirrors be real if our eyes aren't real",
        "most trees are blue",
        "",
        "the moment that truth is organized it becomes a lie.",
        "what if we are all just holograms"
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Original:    '{test}'")
        jaden_cased = to_jaden_case(test)
        print(f"Jaden-Cased: '{jaden_cased}'")
        print()