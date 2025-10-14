
def to_jaden_case(phrase):
    if not phrase:
        return None
    
    result = []
    capitalize_next = True
    
    for c in phrase:
        if c.isspace():
            result.append(c)
            capitalize_next = True
        elif capitalize_next:
            result.append(c.upper())
            capitalize_next = False
        else:
            result.append(c.lower())
    
    return ''.join(result)


def main():
    # Test cases
    print("Test 1:", to_jaden_case("How can mirrors be real if our eyes aren't real"))
    print("Test 2:", to_jaden_case("the quick brown fox jumps over the lazy dog"))
    print("Test 3:", to_jaden_case("I'm a single word"))
    print("Test 4:", to_jaden_case(None))
    print("Test 5:", to_jaden_case(""))


if __name__ == "__main__":
    main()
