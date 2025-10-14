class IntStack:
    def __init__(self):
        self._data = []

    def push(self, value: int) -> None:
        self._data.append(value)

    def pop(self) -> int:
        if not self._data:
            raise IndexError("Stack underflow")
        return self._data.pop()

    def peek(self) -> int:
        if not self._data:
            raise IndexError("Stack underflow")
        return self._data[-1]

    def size(self) -> int:
        return len(self._data)


def main():
    s = IntStack()
    try:
        s.push(1); s.push(2); s.push(3)
        print("Test1 Peek:", s.peek())
    except Exception as e:
        print("Test1 Exception:", e)
    try:
        print("Test2 Pop:", s.pop())
    except Exception as e:
        print("Test2 Exception:", e)
    try:
        print("Test3 Pop:", s.pop())
    except Exception as e:
        print("Test3 Exception:", e)
    try:
        s.push(4)
        print("Test4 Pop:", s.pop())
    except Exception as e:
        print("Test4 Exception:", e)
    try:
        print("Test5 Pop:", s.pop())  # pop 1
        print("Test5 Pop:", s.pop())  # underflow
    except Exception as e:
        print("Test5 Exception:", e)


if __name__ == "__main__":
    main()