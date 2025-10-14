
def expanded_form(num):
    num_str = str(num)
    result = []
    length = len(num_str)
    
    for i in range(length):
        digit = num_str[i]
        if digit != '0':
            result.append(digit + '0' * (length - i - 1))
    
    return ' + '.join(result)


if __name__ == "__main__":
    print(expanded_form(12))      # "10 + 2"
    print(expanded_form(42))      # "40 + 2"
    print(expanded_form(70304))   # "70000 + 300 + 4"
    print(expanded_form(9000))    # "9000"
    print(expanded_form(123456))  # "100000 + 20000 + 3000 + 400 + 50 + 6"
