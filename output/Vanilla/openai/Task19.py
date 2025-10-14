def spin_words(sentence: str) -> str:
    return " ".join([w[::-1] if len(w) >= 5 else w for w in sentence.split(" ")])

if __name__ == "__main__":
    tests = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "Welcome",
        "CodeWars is nice place"
    ]
    for t in tests:
        print(spin_words(t))