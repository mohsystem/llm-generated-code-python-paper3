
def odd_or_even(array):
    if array is None or len(array) == 0:
        array = [0]
    
    total = sum(array)
    return "even" if total % 2 == 0 else "odd"


if __name__ == "__main__":
    print(odd_or_even([0]))
    print(odd_or_even([0, 1, 4]))
    print(odd_or_even([0, -1, -5]))
    print(odd_or_even([]))
    print(odd_or_even([1, 2, 3, 4, 5]))
