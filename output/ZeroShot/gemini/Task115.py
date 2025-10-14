class HardwareRegister:
    """
    This class simulates a hardware register with bit fields using
    properties and bitwise operations for secure and encapsulated access.
    """
    
    # Field definitions: (name, position, bit_width)
    _FIELDS = {
        'enable':     (0, 1),
        'ready':      (1, 1),
        'mode':       (2, 2),
        'error_code': (4, 4),
        'reserved':   (8, 8)
    }

    def __init__(self, initial_value=0):
        # Using a private attribute to store the register's state
        self._register = int(initial_value)

    def _get_field(self, name):
        pos, width = self._FIELDS[name]
        mask = (1 << width) - 1
        return (self._register >> pos) & mask

    def _set_field(self, name, value):
        pos, width = self._FIELDS[name]
        mask = (1 << width) - 1
        max_val = mask

        if not (0 <= value <= max_val):
            raise ValueError(f"{name} must be between 0 and {max_val}, but got {value}")

        # Clear the bits for the field
        self._register &= ~(mask << pos)
        # Set the new value
        self._register |= (value << pos)

    @property
    def enable(self):
        return self._get_field('enable') == 1

    @enable.setter
    def enable(self, value):
        self._set_field('enable', 1 if value else 0)

    @property
    def ready(self):
        return self._get_field('ready') == 1

    @ready.setter
    def ready(self, value):
        self._set_field('ready', 1 if value else 0)

    @property
    def mode(self):
        return self._get_field('mode')

    @mode.setter
    def mode(self, value):
        self._set_field('mode', value)

    @property
    def error_code(self):
        return self._get_field('error_code')

    @error_code.setter
    def error_code(self, value):
        self._set_field('error_code', value)
        
    @property
    def reserved(self):
        return self._get_field('reserved')

    @reserved.setter
    def reserved(self, value):
        self._set_field('reserved', value)

    def __str__(self):
        binary_rep = f"{self._register:016b}"
        return (
            f"Register(binary={binary_rep}) -> "
            f"enable={self.enable}, ready={self.ready}, mode={self.mode}, "
            f"errorCode={self.error_code}, reserved={self.reserved}"
        )

def main():
    print("--- Python Bit Field Simulation ---")
    
    # Test Case 1: Initial state
    print("\n--- Test Case 1: Initial State ---")
    reg1 = HardwareRegister()
    print(reg1)

    # Test Case 2: Setting individual fields
    print("\n--- Test Case 2: Setting Individual Fields ---")
    reg2 = HardwareRegister()
    reg2.enable = True
    reg2.mode = 3  # 11 in binary
    reg2.error_code = 10  # 1010 in binary
    print(reg2)

    # Test Case 3: Setting all fields
    print("\n--- Test Case 3: Setting All Fields ---")
    reg3 = HardwareRegister()
    reg3.enable = True
    reg3.ready = True
    reg3.mode = 1
    reg3.error_code = 5
    reg3.reserved = 255
    print(reg3)

    # Test Case 4: Modifying existing fields
    print("\n--- Test Case 4: Modifying Existing Fields ---")
    reg3.enable = False
    reg3.error_code = 15
    print(reg3)

    # Test Case 5: Invalid input
    print("\n--- Test Case 5: Invalid Input ---")
    reg5 = HardwareRegister()
    try:
        reg5.mode = 4
    except ValueError as e:
        print(f"Caught expected exception: {e}")
    try:
        reg5.error_code = -1
    except ValueError as e:
        print(f"Caught expected exception: {e}")
    print(f"State after invalid attempts: {reg5}")

if __name__ == "__main__":
    main()