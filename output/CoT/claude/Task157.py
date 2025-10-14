
import sys

class MemoryResource:
    """Memory resource class to track allocations safely"""
    
    def __init__(self, size):
        if size <= 0:
            raise ValueError("Size must be positive")
        if size > sys.maxsize // 2:
            raise ValueError("Size too large")
        self.size = size
        self.data = bytearray(size)
        self.allocated = True
    
    def deallocate(self):
        if not self.allocated:
            raise RuntimeError("Resource already deallocated")
        # Clear sensitive data before deallocation
        for i in range(len(self.data)):
            self.data[i] = 0
        self.allocated = False
    
    def is_allocated(self):
        return self.allocated
    
    def get_size(self):
        return self.size

def allocate_memory(size):
    """Safely allocate memory resource"""
    if size <= 0 or size > sys.maxsize // 2:
        raise ValueError("Invalid memory size")
    return MemoryResource(size)

def deallocate_memory(resource):
    """Safely deallocate memory resource"""
    if resource is None:
        raise ValueError("Resource cannot be None")
    resource.deallocate()

def main():
    print("Test Case 1: Basic allocation and deallocation")
    try:
        res1 = allocate_memory(1024)
        print(f"Allocated: {res1.get_size()} bytes, Status: {res1.is_allocated()}")
        deallocate_memory(res1)
        print(f"Deallocated, Status: {res1.is_allocated()}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 2: Multiple allocations")
    try:
        resources = []
        for i in range(1, 4):
            res = allocate_memory(512 * i)
            resources.append(res)
            print(f"Allocated resource {i}: {res.get_size()} bytes")
        for res in resources:
            deallocate_memory(res)
        print("All resources deallocated")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 3: Invalid size (negative)")
    try:
        res3 = allocate_memory(-100)
    except Exception as e:
        print(f"Caught expected error: {e}")
    
    print("\\nTest Case 4: Double deallocation prevention")
    try:
        res4 = allocate_memory(2048)
        deallocate_memory(res4)
        deallocate_memory(res4)
    except Exception as e:
        print(f"Caught expected error: {e}")
    
    print("\\nTest Case 5: None resource deallocation")
    try:
        deallocate_memory(None)
    except Exception as e:
        print(f"Caught expected error: {e}")

if __name__ == "__main__":
    main()
