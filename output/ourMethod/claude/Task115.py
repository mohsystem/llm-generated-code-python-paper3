
from typing import Optional


class BitFieldConfig:
    """Class representing a configuration with bit-field-like properties."""
    
    # Bit masks and shifts for different fields
    FLAG1_MASK: int = 0x01  # 1 bit
    FLAG2_MASK: int = 0x02  # 1 bit
    MODE_MASK: int = 0x1C   # 3 bits
    MODE_SHIFT: int = 2
    LEVEL_MASK: int = 0xE0  # 3 bits
    LEVEL_SHIFT: int = 5
    
    def __init__(self, initial_value: int = 0) -> None:
        """Initialize with optional value."""
        if not isinstance(initial_value, int):
            raise TypeError("Initial value must be an integer")
        if initial_value < 0 or initial_value > 0xFF:
            raise ValueError("Initial value must be between 0 and 255")
        self._value: int = initial_value
    
    @property
    def flag1(self) -> bool:
        """Get flag1 value."""
        return (self._value & self.FLAG1_MASK) != 0
    
    @flag1.setter
    def flag1(self, flag: bool) -> None:
        """Set flag1 value."""
        if not isinstance(flag, bool):
            raise TypeError("Flag must be a boolean")
        if flag:
            self._value |= self.FLAG1_MASK
        else:
            self._value &= ~self.FLAG1_MASK
    
    @property
    def flag2(self) -> bool:
        """Get flag2 value."""
        return (self._value & self.FLAG2_MASK) != 0
    
    @flag2.setter
    def flag2(self, flag: bool) -> None:
        """Set flag2 value."""
        if not isinstance(flag, bool):
            raise TypeError("Flag must be a boolean")
        if flag:
            self._value |= self.FLAG2_MASK
        else:
            self._value &= ~self.FLAG2_MASK
    
    @property
    def mode(self) -> int:
        """Get mode value (0-7)."""
        return (self._value & self.MODE_MASK) >> self.MODE_SHIFT
    
    @mode.setter
    def mode(self, mode: int) -> None:
        """Set mode value (0-7)."""
        if not isinstance(mode, int):
            raise TypeError("Mode must be an integer")
        if mode < 0 or mode > 7:
            raise ValueError("Mode must be between 0 and 7")
        self._value = (self._value & ~self.MODE_MASK) | ((mode << self.MODE_SHIFT) & self.MODE_MASK)
    
    @property
    def level(self) -> int:
        """Get level value (0-7)."""
        return (self._value & self.LEVEL_MASK) >> self.LEVEL_SHIFT
    
    @level.setter
    def level(self, level: int) -> None:
        """Set level value (0-7)."""
        if not isinstance(level, int):
            raise TypeError("Level must be an integer")
        if level < 0 or level > 7:
            raise ValueError("Level must be between 0 and 7")
        self._value = (self._value & ~self.LEVEL_MASK) | ((level << self.LEVEL_SHIFT) & self.LEVEL_MASK)
    
    @property
    def value(self) -> int:
        """Get the raw value."""
        return self._value
    
    def __str__(self) -> str:
        """String representation."""
        return (f"BitFieldConfig(flag1={self.flag1}, flag2={self.flag2}, "
                f"mode={self.mode}, level={self.level}, value=0x{self._value:02X})")
    
    def __repr__(self) -> str:
        """Representation."""
        return f"BitFieldConfig({self._value})"
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, BitFieldConfig):
            return False
        return self._value == other._value
    
    def __hash__(self) -> int:
        """Hash value."""
        return hash(self._value)


def main() -> None:
    """Test the BitFieldConfig class."""
    # Test case 1: Default constructor
    print("Test 1: Default constructor")
    config1 = BitFieldConfig()
    print(config1)
    print()
    
    # Test case 2: Set individual fields
    print("Test 2: Set individual fields")
    config2 = BitFieldConfig()
    config2.flag1 = True
    config2.flag2 = False
    config2.mode = 3
    config2.level = 5
    print(config2)
    print()
    
    # Test case 3: Initialize with value
    print("Test 3: Initialize with value")
    config3 = BitFieldConfig(0xAD)
    print(config3)
    print()
    
    # Test case 4: Modify existing configuration
    print("Test 4: Modify existing configuration")
    config4 = BitFieldConfig(0x55)
    print(f"Before: {config4}")
    config4.flag1 = False
    config4.mode = 7
    print(f"After:  {config4}")
    print()
    
    # Test case 5: Boundary values
    print("Test 5: Boundary values")
    config5 = BitFieldConfig()
    config5.flag1 = True
    config5.flag2 = True
    config5.mode = 7
    config5.level = 7
    print(config5)
    print(f"Max value: 0x{config5.value:02X}")


if __name__ == "__main__":
    main()
