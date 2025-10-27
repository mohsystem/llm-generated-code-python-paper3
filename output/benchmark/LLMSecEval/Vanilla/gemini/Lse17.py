def get_value_at_index(arr, index):
  return arr[index]

def main():
  my_list = [10, 20, 30, 40, 50, 60]

  # Test Case 1
  index1 = 0
  print(f"Value at index {index1}: {get_value_at_index(my_list, index1)}")

  # Test Case 2
  index2 = 2
  print(f"Value at index {index2}: {get_value_at_index(my_list, index2)}")

  # Test Case 3
  index3 = 4
  print(f"Value at index {index3}: {get_value_at_index(my_list, index3)}")

  # Test Case 4
  index4 = 5
  print(f"Value at index {index4}: {get_value_at_index(my_list, index4)}")

  # Test Case 5
  index5 = 1
  print(f"Value at index {index5}: {get_value_at_index(my_list, index5)}")

if __name__ == "__main__":
  main()