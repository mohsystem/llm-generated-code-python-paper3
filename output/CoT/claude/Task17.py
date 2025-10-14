
def to_jaden_case(phrase):
    if phrase is None or phrase == "":
        return None
    
    result = []
    capitalize_next = True
    
    for char in phrase:
        if char.isspace():
            result.append(char)
            capitalize_next = True
        elif capitalize_next:
            result.append(char.upper())
            capitalize_next = False
        else:
            result.append(char)
    
    return ''.join(result)

if __name__ == "__main__":
    print("Test 1:", to_jaden_case("How can mirrors be real if our eyes aren't real"))
    print("Test 2:", to_jaden_case("this is a test"))
    print("Test 3:", to_jaden_case("i love programming"))
    print("Test 4:", to_jaden_case(None))
    print("Test 5:", to_jaden_case(""))
