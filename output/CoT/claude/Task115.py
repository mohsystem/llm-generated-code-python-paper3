
class Task115:
    def __init__(self):
        # Simulating bit fields for a network packet header
        self._version = 0       # 4 bits (0-15)
        self._priority = 0      # 3 bits (0-7)
        self._flag = 0          # 1 bit (0-1)
        self._payload_length = 0 # 8 bits (0-255)
    
    def set_version(self, value):
        if not isinstance(value, int) or value < 0 or value > 15:
            print("Error: Version must be 0-15")
            return False
        self._version = value & 0x0F
        return True
    
    def set_priority(self, value):
        if not isinstance(value, int) or value < 0 or value > 7:
            print("Error: Priority must be 0-7")
            return False
        self._priority = value & 0x07
        return True
    
    def set_flag(self, value):
        if not isinstance(value, int) or value < 0 or value > 1:
            print("Error: Flag must be 0 or 1")
            return False
        self._flag = value & 0x01
        return True
    
    def set_payload_length(self, value):
        if not isinstance(value, int) or value < 0 or value > 255:
            print("Error: PayloadLength must be 0-255")
            return False
        self._payload_length = value & 0xFF
        return True
    
    def get_version(self):
        return self._version
    
    def get_priority(self):
        return self._priority
    
    def get_flag(self):
        return self._flag
    
    def get_payload_length(self):
        return self._payload_length
    
    def pack_to_int(self):
        return ((self._version & 0x0F) << 12)
    
    def unpack_from_int(self, packed):
        if not isinstance(packed, int) or packed < 0 or packed > 0xFFFF:
            print("Error: Invalid packed value")
            return False
        self._version = (packed >> 12) & 0x0F
        self._priority = (packed >> 9) & 0x07
        self._flag = (packed >> 8) & 0x01
        self._payload_length = packed & 0xFF
        return True
    
    def __str__(self):
        return (f"Version: {self._version}, Priority: {self._priority}, "
                f"Flag: {self._flag}, PayloadLength: {self._payload_length} "
                f"(Packed: 0x{self.pack_to_int():04X})"
                f"")

def main():
    print("=== Bit Field Struct Demonstration ===\\n")
    
    # Test Case 1: Normal values
    print("Test Case 1: Setting normal values")
    packet1 = Task115()
    packet1.set_version(4)
    packet1.set_priority(3)
    packet1.set_flag(1)
    packet1.set_payload_length(128)
    print(packet1)
    print()
    
    # Test Case 2: Maximum values
    print("Test Case 2: Setting maximum values")
    packet2 = Task115()
    packet2.set_version(15)
    packet2.set_priority(7)
    packet2.set_flag(1)
    packet2.set_payload_length(255)
    print(packet2)
    print()
    
    # Test Case 3: Minimum values
    print("Test Case 3: Setting minimum values")
    packet3 = Task115()
    packet3.set_version(0)
    packet3.set_priority(0)
    packet3.set_flag(0)
    packet3.set_payload_length(0)
    print(packet3)
    print()
    
    # Test Case 4: Invalid values (should show errors)
    print("Test Case 4: Attempting invalid values")
    packet4 = Task115()
    packet4.set_version(20)
    packet4.set_priority(10)
    packet4.set_flag(2)
    packet4.set_payload_length(300)
    print(packet4)
    print()
    
    # Test Case 5: Pack and unpack
    print("Test Case 5: Pack and unpack operations")
    packet5 = Task115()
    packet5.set_version(7)
    packet5.set_priority(5)
    packet5.set_flag(1)
    packet5.set_payload_length(200)
    print(f"Original: {packet5}")
    packed = packet5.pack_to_int()
    packet6 = Task115()
    packet6.unpack_from_int(packed)
    print(f"Unpacked: {packet6}")


if __name__ == "__main__":
    main()
