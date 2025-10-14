
class MemoryResource:
    def __init__(self, size):
        self.size = size
        self.data = [0] * size
        print(f"Allocated memory for {size} integers")
    
    def set_data(self, index, value):
        if 0 <= index < self.size:
            self.data[index] = value
    
    def get_data(self, index):
        if 0 <= index < self.size:
            return self.data[index]
        return -1
    
    def deallocate(self):
        self.data = None
        print(f"Deallocated memory for {self.size} integers")
    
    def get_size(self):
        return self.size


def allocate_memory(size):
    return MemoryResource(size)


def deallocate_memory(resource):
    if resource is not None:
        resource.deallocate()


if __name__ == "__main__":
    print("Test Case 1: Allocate and deallocate 10 integers")
    res1 = allocate_memory(10)
    res1.set_data(0, 100)
    res1.set_data(5, 500)
    print(f"Data at index 0: {res1.get_data(0)}")
    print(f"Data at index 5: {res1.get_data(5)}")
    deallocate_memory(res1)
    print()
    
    print("Test Case 2: Allocate and deallocate 100 integers")
    res2 = allocate_memory(100)
    for i in range(10):
        res2.set_data(i, i * 10)
    print(f"Data at index 7: {res2.get_data(7)}")
    deallocate_memory(res2)
    print()
    
    print("Test Case 3: Allocate and deallocate 1 integer")
    res3 = allocate_memory(1)
    res3.set_data(0, 999)
    print(f"Data at index 0: {res3.get_data(0)}")
    deallocate_memory(res3)
    print()
    
    print("Test Case 4: Allocate and deallocate 1000 integers")
    res4 = allocate_memory(1000)
    res4.set_data(999, 12345)
    print(f"Data at index 999: {res4.get_data(999)}")
    deallocate_memory(res4)
    print()
    
    print("Test Case 5: Multiple allocations and deallocations")
    res5a = allocate_memory(50)
    res5b = allocate_memory(75)
    res5a.set_data(25, 2500)
    res5b.set_data(50, 5000)
    print(f"Resource A at index 25: {res5a.get_data(25)}")
    print(f"Resource B at index 50: {res5b.get_data(50)}")
    deallocate_memory(res5a)
    deallocate_memory(res5b)
