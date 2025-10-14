def concat_strings(parts):
    return ''.join(s for s in parts if s is not None)

if __name__ == "__main__":
    tests = [
        ["Hello", " ", "World"],
        ["", "abc", "", "123"],
        ["Join", "-", "these", "-", "together"],
        ["multi", "", "ple", " ", "strings"],
        ["Unicode:", " ", "😊", " ", "测试"]
    ]
    for t in tests:
        print(concat_strings(t))