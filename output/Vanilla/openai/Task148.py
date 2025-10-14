class Stack:
    def __init__(self):
        self._data = []

    def push(self, value):
        self._data.append(value)

    def pop(self):
        if not self._data:
            raise IndexError("Stack underflow")
        return self._data.pop()

    def peek(self):
        if not self._data:
            raise IndexError("Stack is empty")
        return self._data[-1]

    def is_empty(self):
        return len(self._data) == 0

    def size(self):
        return len(self._data)


def main():
    s = Stack()
    s.push(10)
    s.push(20)
    s.push(30)
    print(s.peek())  # Test 1
    print(s.pop())   # Test 2
    s.push(40)
    print(s.peek())  # Test 3
    print(s.pop())   # Test 4
    print(s.pop())   # Test 5


if __name__ == "__main__":
    main()