def find_missing_letter(array):
    for i in range(1, len(array)):
        if ord(array[i]) != ord(array[i - 1]) + 1:
            return chr(ord(array[i - 1]) + 1)
    return chr(ord(array[-1]) + 1)

if __name__ == "__main__":
    tests = [
        ['a','b','c','d','f'],
        ['O','Q','R','S'],
        ['b','c','d','e','g'],
        ['A','B','D'],
        ['m','n','p','q','r'],
    ]
    for t in tests:
        print(find_missing_letter(t))