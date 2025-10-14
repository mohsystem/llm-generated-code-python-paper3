
import sys

class MemoryResource:
    def __init__(self, size):
        if size <= 0:
            raise ValueError("Size must be positive")
        self.data = bytearray(size)
        self.allocated = True
        print(f"Memory allocated: {size} bytes")
    
    def deallocate(self):
        if self.allocated:
            self.data = None
            self.allocated = False
            print("Memory deallocated")
    
    def is_allocated(self):
        return self.allocated
    
    def get_size(self):
        return len(self.data) if self.allocated and self.data is not None else 0

def allocate_memory(size):
    return MemoryResource(size)

def deallocate_memory(resource):
    if resource is not None:
        resource.deallocate()

if __name__ == "__main__":
    print("Test Case 1: Allocate and deallocate 1024 bytes")
    res1 = allocate_memory(1024)
    print(f"Is allocated: {res1.is_allocated()}")
    deallocate_memory(res1)
    print(f"Is allocated after deallocation: {res1.is_allocated()}")
    print()
    
    print("Test Case 2: Allocate and deallocate 2048 bytes")
    res2 = allocate_memory(2048)
    print(f"Size: {res2.get_size()}")
    deallocate_memory(res2)
    print()
    
    print("Test Case 3: Multiple allocations")
    res3 = allocate_memory(512)
    res4 = allocate_memory(256)
    deallocate_memory(res3)
    deallocate_memory(res4)
    print()
    
    print("Test Case 4: Deallocate null resource")
    deallocate_memory(None)
    print("No error on null deallocation")
    print()
    
    print("Test Case 5: Large allocation")
    res5 = allocate_memory(1048576)  # 1MB
    print(f"Large allocation size: {res5.get_size()}")
    deallocate_memory(res5)
