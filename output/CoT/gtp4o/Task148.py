class Stack:
    def __init__(self):
        self._data = []

    # Push returns True on success
    def push(self, value: int) -> bool:
        try:
            self._data.append(value)
            return True
        except MemoryError:
            return False

    # Pop returns (ok, value). If not ok, value is None
    def pop(self):
        if not self._data:
            return (False, None)
        return (True, self._data.pop())

    # Peek returns (ok, value). If not ok, value is None
    def peek(self):
        if not self._data:
            return (False, None)
        return (True, self._data[-1])

    def is_empty(self) -> bool:
        return len(self._data) == 0

    def size(self) -> int:
        return len(self._data)


if __name__ == "__main__":
    s = Stack()

    # Test 1: Push 1,2,3 then peek
    t1a = s.push(1)
    t1b = s.push(2)
    t1c = s.push(3)
    t1ok, t1val = s.peek()
    print(f"Test1: pushes={t1a},{t1b},{t1c} peekOk={t1ok} peekVal={t1val}")

    # Test 2: Pop once
    t2ok, t2val = s.pop()
    print(f"Test2: popOk={t2ok} val={t2val}")

    # Test 3: Peek after pop
    t3ok, t3val = s.peek()
    print(f"Test3: peekOk={t3ok} val={t3val}")

    # Test 4: Pop remaining and attempt extra pop
    t4a_ok, t4a_val = s.pop()
    t4b_ok, t4b_val = s.pop()
    t4c_ok, t4c_val = s.pop()  # should fail
    print(f"Test4: popVals={t4a_val if t4a_ok else None},{t4b_val if t4b_ok else None} extraPopOk={t4c_ok}")

    # Test 5: Push after empty and peek
    t5a = s.push(42)
    t5b_ok, t5b_val = s.peek()
    print(f"Test5: pushOk={t5a} peekOk={t5b_ok} val={t5b_val if t5b_ok else None}")