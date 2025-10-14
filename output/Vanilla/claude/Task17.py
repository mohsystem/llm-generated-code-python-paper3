
def to_jaden_case(phrase):
    if phrase is None or phrase == "":
        return None
    
    result = []
    capitalize_next = True
    
    for c in phrase:
        if c.isspace():
            result.append(c)
            capitalize_next = True
        else:
            if capitalize_next and c.isalpha():
                result.append(c.upper())
                capitalize_next = False
            else:
                result.append(c)
    
    return ''.join(result)


if __name__ == "__main__":
    # Test cases
    print(to_jaden_case("How can mirrors be real if our eyes aren't real"))
    print(to_jaden_case("the quick brown fox jumps over the lazy dog"))
    print(to_jaden_case("i love programming"))
    print(to_jaden_case(""))
    print(to_jaden_case(None))
