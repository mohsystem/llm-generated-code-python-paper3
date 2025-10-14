def expanded_form(num):
    s = str(num)
    parts = []
    for i, digit in enumerate(s):
        if digit != '0':
            num_zeros = len(s) - 1 - i
            parts.append(digit + '0' * num_zeros)
    return ' + '.join(parts)

# Main block with test cases
if __name__ == '__main__':
    print(f"12 -> {expanded_form(12)}")
    print(f"42 -> {expanded_form(42)}")
    print(f"70304 -> {expanded_form(70304)}")
    print(f"999 -> {expanded_form(999)}")
    print(f"800000 -> {expanded_form(800000)}")