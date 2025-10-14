class StatusRegister:
    """
    In Python, bit fields are not a direct language feature.
    This class simulates them using bitwise operations and properties
    on a single internal integer.

    Bit field layout:
    Bit 0:      active (1 bit)
    Bits 1-3:   mode (3 bits, values 0-7)
    Bits 4-7:   error_code (4 bits, values 0-15)
    """

    def __init__(self, active, mode, error_code):
        # Pack the values into a single integer during initialization
        self._register = self.pack(active, mode, error_code)

    @staticmethod
    def pack(active, mode, error_code):
        """Packs individual values into a single integer."""
        if not 0 <= mode <= 7:
            raise ValueError("Mode must be between 0 and 7.")
        if not 0 <= error_code <= 15:
            raise ValueError("Error code must be between 0 and 15.")

        active_bit = 1 if active else 0
        # Combine using bitwise OR and left shifts
        return active_bit | (mode << 1) | (error_code << 4)

    # Use properties to get/set values, providing a clean interface
    @property
    def active(self):
        return (self._register & 0b1) != 0

    @property
    def mode(self):
        return (self._register >> 1) & 0b111

    @property
    def error_code(self):
        return (self._register >> 4) & 0b1111

    def __str__(self):
        return (f"Packed Value: {self._register} (Binary: {self._register:08b})\n"
                f"  -> Unpacked: active={self.active}, mode={self.mode}, error_code={self.error_code}")


def main():
    """Main function with test cases."""
    print("Python Bit Field Simulation:")

    test_cases = [
        (True, 5, 10),   # Case 1: General case
        (False, 0, 0),    # Case 2: All zero values
        (True, 7, 15),   # Case 3: All max values
        (False, 1, 8),    # Case 4: Another general case
        (True, 3, 4)     # Case 5: Mid-range values
    ]

    for i, (active, mode, error_code) in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        try:
            status = StatusRegister(active, mode, error_code)
            print(status)
        except ValueError as e:
            print(f"Error creating status: {e}")


if __name__ == "__main__":
    main()