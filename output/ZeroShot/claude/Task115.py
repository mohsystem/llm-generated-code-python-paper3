
class Task115:
    def __init__(self):
        self._data = 0
        
        # Bit field masks and shifts
        self.FLAG1_MASK = 0x01      # 1 bit
        self.FLAG2_MASK = 0x02      # 1 bit
        self.VALUE_MASK = 0x3C      # 4 bits (positions 2-5)
        self.VALUE_SHIFT = 2
        self.STATUS_MASK = 0xC0     # 2 bits (positions 6-7)
        self.STATUS_SHIFT = 6
    
    def set_flag1(self, value):
        if value:
            self._data |= self.FLAG1_MASK
        else:
            self._data &= ~self.FLAG1_MASK
    
    def get_flag1(self):
        return (self._data & self.FLAG1_MASK) != 0
    
    def set_flag2(self, value):
        if value:
            self._data |= self.FLAG2_MASK
        else:
            self._data &= ~self.FLAG2_MASK
    
    def get_flag2(self):
        return (self._data & self.FLAG2_MASK) != 0
    
    def set_value(self, value):
        if value < 0 or value > 15:
            raise ValueError("Value must be between 0 and 15")
        self._data = (self._data & ~self.VALUE_MASK) | ((value << self.VALUE_SHIFT) & self.VALUE_MASK)
    
    def get_value(self):
        return (self._data & self.VALUE_MASK) >> self.VALUE_SHIFT
    
    def set_status(self, status):
        if status < 0 or status > 3:
            raise ValueError("Status must be between 0 and 3")
        self._data = (self._data & ~self.STATUS_MASK) | ((status << self.STATUS_SHIFT) & self.STATUS_MASK)
    
    def get_status(self):
        return (self._data & self.STATUS_MASK) >> self.STATUS_SHIFT
    
    def __str__(self):
        return f"BitField{{flag1={self.get_flag1()}, flag2={self.get_flag2()}, value={self.get_value()}, status={self.get_status()}}}"


if __name__ == "__main__":
    print("Test Case 1: Initialize and check default values")
    bf1 = Task115()
    print(bf1)
    
    print("\\nTest Case 2: Set all flags and values")
    bf2 = Task115()
    bf2.set_flag1(True)
    bf2.set_flag2(True)
    bf2.set_value(10)
    bf2.set_status(2)
    print(bf2)
    
    print("\\nTest Case 3: Set partial values")
    bf3 = Task115()
    bf3.set_flag1(True)
    bf3.set_value(15)
    print(bf3)
    
    print("\\nTest Case 4: Toggle flags")
    bf4 = Task115()
    bf4.set_flag1(True)
    bf4.set_flag2(False)
    bf4.set_value(7)
    bf4.set_status(3)
    print(bf4)
    bf4.set_flag1(False)
    bf4.set_flag2(True)
    print(bf4)
    
    print("\\nTest Case 5: Maximum values")
    bf5 = Task115()
    bf5.set_flag1(True)
    bf5.set_flag2(True)
    bf5.set_value(15)
    bf5.set_status(3)
    print(bf5)
