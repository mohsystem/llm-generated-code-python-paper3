
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    return -1  # Return -1 for invalid index

if __name__ == "__main__":
    # Test case 1
    index1 = 0
    print(f"Index {index1}: {get_value_at_index(index1)}")
    
    # Test case 2
    index2 = 5
    print(f"Index {index2}: {get_value_at_index(index2)}")
    
    # Test case 3
    index3 = 9
    print(f"Index {index3}: {get_value_at_index(index3)}")
    
    # Test case 4
    index4 = -1
    print(f"Index {index4}: {get_value_at_index(index4)}")
    
    # Test case 5
    index5 = 10
    print(f"Index {index5}: {get_value_at_index(index5)}")
