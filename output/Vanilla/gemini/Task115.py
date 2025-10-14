class DateBitField:
    """
    Simulates C-style bit fields for a date using a single integer.
    The bit layout within a 16-bit integer is: YYYYYYYMMMMDDDDD
    - Year: 7 bits (0-127), representing an offset from the year 2000.
    - Month: 4 bits (1-12)
    - Day: 5 bits (1-31)
    """
    # Define masks to isolate each field
    _DAY_MASK = 0x1F      # Binary: 0000000000011111
    _MONTH_MASK = 0x1E0     # Binary: 0000000111100000
    _YEAR_MASK = 0xFE00    # Binary: 1111111000000000
    
    # Define bit shift counts for each field
    _MONTH_SHIFT = 5
    _YEAR_SHIFT = 9

    def __init__(self, day: int, month: int, year: int):
        """
        Initializes the date and packs it into a single integer.
        :param day: Day of the month (1-31)
        :param month: Month of the year (1-12)
        :param year: Year offset from 2000 (e.g., 23 for 2023)
        """
        if not (1 <= day <= 31):
            raise ValueError("Day must be between 1 and 31")
        if not (1 <= month <= 12):
            raise ValueError("Month must be between 1 and 12")
        if not (0 <= year <= 127):
            raise ValueError("Year offset must be between 0 and 127")
            
        self._data = (year << self._YEAR_SHIFT) | (month << self._MONTH_SHIFT) | day

    @property
    def day(self) -> int:
        return self._data & self._DAY_MASK

    @property
    def month(self) -> int:
        return (self._data & self._MONTH_MASK) >> self._MONTH_SHIFT

    @property
    def year(self) -> int:
        return (self._data & self._YEAR_MASK) >> self._YEAR_SHIFT

    def __str__(self) -> str:
        return f"Date: {self.month:02d}/{self.day:02d}/{self.year + 2000}"

def main():
    """Main function with test cases."""
    print("Python Test Cases (Simulated Bit Fields):")
    
    test_cases = [
        (1, 1, 23),    # Test Case 1
        (31, 12, 99),  # Test Case 2
        (29, 2, 24),   # Test Case 3
        (15, 8, 47),   # Test Case 4
        (4, 7, 76)     # Test Case 5
    ]

    for day, month, year in test_cases:
        try:
            date = DateBitField(day, month, year)
            print(date)
        except ValueError as e:
            print(f"Error creating date {month}/{day}/{year+2000}: {e}")

if __name__ == "__main__":
    main()