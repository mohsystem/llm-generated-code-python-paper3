
class Task115:
    # Python doesn't support bit fields directly, so we use bit manipulation
    class BitFields:
        def __init__(self):
            self.value = 0
        
        # Field 1: 3 bits (0-2)
        def set_field1(self, val):
            self.value = (self.value & ~0x07) | (val & 0x07)
        
        def get_field1(self):
            return self.value & 0x07
        
        # Field 2: 5 bits (3-7)
        def set_field2(self, val):
            self.value = (self.value & ~0xF8) | ((val & 0x1F) << 3)
        
        def get_field2(self):
            return (self.value >> 3) & 0x1F
        
        # Field 3: 8 bits (8-15)
        def set_field3(self, val):
            self.value = (self.value & ~0xFF00) | ((val & 0xFF) << 8)
        
        def get_field3(self):
            return (self.value >> 8) & 0xFF
        
        def display(self):
            print(f"Field1: {self.get_field1()}, Field2: {self.get_field2()}, Field3: {self.get_field3()}")


if __name__ == "__main__":
    # Test case 1
    bf1 = Task115.BitFields()
    bf1.set_field1(5)
    bf1.set_field2(20)
    bf1.set_field3(100)
    print("Test 1: ", end="")
    bf1.display()
    
    # Test case 2
    bf2 = Task115.BitFields()
    bf2.set_field1(7)
    bf2.set_field2(31)
    bf2.set_field3(255)
    print("Test 2: ", end="")
    bf2.display()
    
    # Test case 3
    bf3 = Task115.BitFields()
    bf3.set_field1(0)
    bf3.set_field2(0)
    bf3.set_field3(0)
    print("Test 3: ", end="")
    bf3.display()
    
    # Test case 4
    bf4 = Task115.BitFields()
    bf4.set_field1(3)
    bf4.set_field2(15)
    bf4.set_field3(128)
    print("Test 4: ", end="")
    bf4.display()
    
    # Test case 5
    bf5 = Task115.BitFields()
    bf5.set_field1(1)
    bf5.set_field2(10)
    bf5.set_field3(50)
    print("Test 5: ", end="")
    bf5.display()
