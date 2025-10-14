from typing import Self

class HardwareFlags:
    """
    A class that simulates a C-style struct with bit fields using bitwise operations.
    It packs multiple boolean and small integer values into a single integer field.

    Bit layout (from right to left, LSB is bit 0):
    - Bit 0: is_active (1 bit)
    - Bit 1: is_ready (1 bit)
    - Bits 2-3: error_state (2 bits, values 0-3)
    - Bits 4-6: mode (3 bits, values 0-7)
    """

    # Masks and shifts for each field
    _IS_ACTIVE_MASK = 1 << 0
    _IS_READY_MASK = 1 << 1

    _ERROR_STATE_SHIFT = 2
    _ERROR_STATE_MASK = 0b11 << _ERROR_STATE_SHIFT

    _MODE_SHIFT = 4
    _MODE_MASK = 0b111 << _MODE_SHIFT

    def __init__(self) -> None:
        self._flags: int = 0

    @property
    def is_active(self) -> bool:
        """Getter for is_active flag (1 bit)."""
        return (self._flags & self._IS_ACTIVE_MASK) != 0

    @is_active.setter
    def is_active(self, value: bool) -> None:
        """Setter for is_active flag."""
        if value:
            self._flags |= self._IS_ACTIVE_MASK
        else:
            self._flags &= ~self._IS_ACTIVE_MASK

    @property
    def is_ready(self) -> bool:
        """Getter for is_ready flag (1 bit)."""
        return (self._flags & self._IS_READY_MASK) != 0

    @is_ready.setter
    def is_ready(self, value: bool) -> None:
        """Setter for is_ready flag."""
        if value:
            self._flags |= self._IS_READY_MASK
        else:
            self._flags &= ~self._IS_READY_MASK

    @property
    def error_state(self) -> int:
        """Getter for error_state (2 bits)."""
        return (self._flags & self._ERROR_STATE_MASK) >> self._ERROR_STATE_SHIFT

    @error_state.setter
    def error_state(self, value: int) -> None:
        """Setter for error_state."""
        if not 0 <= value <= 3:
            raise ValueError("Error state must be between 0 and 3.")
        # Clear the old bits first, then set the new ones
        self._flags &= ~self._ERROR_STATE_MASK
        self._flags |= (value << self._ERROR_STATE_SHIFT)

    @property
    def mode(self) -> int:
        """Getter for mode (3 bits)."""
        return (self._flags & self._MODE_MASK) >> self._MODE_SHIFT

    @mode.setter
    def mode(self, value: int) -> None:
        """Setter for mode."""
        if not 0 <= value <= 7:
            raise ValueError("Mode must be between 0 and 7.")
        self._flags &= ~self._MODE_MASK
        self._flags |= (value << self._MODE_SHIFT)

    def __str__(self) -> str:
        return (f"HardwareFlags(is_active={self.is_active}, is_ready={self.is_ready}, "
                f"error_state={self.error_state}, mode={self.mode}, raw_value={self._flags})")


def main() -> None:
    """Main function with test cases."""
    print("--- Python Bit Field Simulation Test Cases ---")
    
    # Test Case 1: All fields off
    flags1 = HardwareFlags()
    print(f"Test Case 1: {flags1}")
    
    # Test Case 2: Setting individual fields
    flags2 = HardwareFlags()
    flags2.is_active = True
    flags2.mode = 5
    print(f"Test Case 2: {flags2}")
    
    # Test Case 3: Setting all fields
    flags3 = HardwareFlags()
    flags3.is_active = True
    flags3.is_ready = True
    flags3.error_state = 3
    flags3.mode = 7
    print(f"Test Case 3: {flags3}")
    
    # Test Case 4: Setting and then changing fields
    flags4 = HardwareFlags()
    flags4.is_ready = True
    flags4.error_state = 1
    flags4.mode = 4
    print(f"Test Case 4 (before): {flags4}")
    flags4.is_ready = False
    flags4.error_state = 2
    print(f"Test Case 4 (after):  {flags4}")
    
    # Test Case 5: Zero values for multi-bit fields
    flags5 = HardwareFlags()
    flags5.is_active = True
    flags5.error_state = 0
    flags5.mode = 0
    print(f"Test Case 5: {flags5}")


if __name__ == "__main__":
    main()