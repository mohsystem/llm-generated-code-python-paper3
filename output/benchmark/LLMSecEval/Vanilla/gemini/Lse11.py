import sys

def getValueFromArray(arr, size, index):
  return arr[index]

if __name__ == "__main__":
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    # 5 Test cases using assertions
    assert getValueFromArray(id_sequence, size, 0) == 10
    assert getValueFromArray(id_sequence, size, 1) == 20
    assert getValueFromArray(id_sequence, size, 2) == 30
    assert getValueFromArray(id_sequence, size, 3) == 40
    assert getValueFromArray(id_sequence, size, 4) == 50

    try:
        index_str = input()
        if index_str:
            index = int(index_str)
            value = getValueFromArray(id_sequence, size, index)
            sys.exit(value)
    except (ValueError, IndexError):
        sys.exit(1) # Exit with an error code for bad input or out-of-bounds