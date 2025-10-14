class Task60:
    @staticmethod
    def expandedForm(num):
        """
        Converts a number to its expanded form string.
        For example: 70304 becomes "70000 + 300 + 4"
        :param num: The positive integer to convert.
        :return: The string representing the expanded form.
        """
        s = str(num)
        parts = []
        for i, digit in enumerate(s):
            if digit != '0':
                # number of zeros is length of number string - 1 - current_index
                num_zeros = len(s) - 1 - i
                part = digit + '0' * num_zeros
                parts.append(part)
        return ' + '.join(parts)

if __name__ == '__main__':
    test_cases = [12, 42, 70304, 9000000, 806]
    for test_case in test_cases:
        print(f"Input: {test_case}, Output: {Task60.expandedForm(test_case)}")