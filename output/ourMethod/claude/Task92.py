
import threading
from typing import Optional

class ThreadSafeCounter:
    def __init__(self):
        self._lock = threading.Lock()
        self._current_counter: int = 0
    
    def access_shared_resource(self, thread_name: Optional[str], max_counter: int) -> bool:
        if not thread_name or not isinstance(thread_name, str):
            return False
        if not isinstance(max_counter, int) or max_counter < 0:
            return False
        
        if self._current_counter <= max_counter:
            with self._lock:
                if self._current_counter <= max_counter:
                    self._current_counter += 1
                    print(f"Thread {thread_name} is accessing currentCounter: {self._current_counter}")
                    return True
        return False
    
    def reset_counter(self) -> None:
        with self._lock:
            self._current_counter = 0
    
    def get_current_counter(self) -> int:
        with self._lock:
            return self._current_counter


def main() -> None:
    counter = ThreadSafeCounter()
    
    print("Test Case 1: Multiple threads with maxCounter=5")
    counter.reset_counter()
    threads = []
    for i in range(3):
        t = threading.Thread(target=counter.access_shared_resource, args=(f"T{i}", 5))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(f"Final counter: {counter.get_current_counter()}\\n")
    
    print("Test Case 2: Threads exceeding maxCounter")
    counter.reset_counter()
    threads = []
    for i in range(8):
        t = threading.Thread(target=counter.access_shared_resource, args=(f"T{i}", 5))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(f"Final counter: {counter.get_current_counter()}\\n")
    
    print("Test Case 3: maxCounter=0")
    counter.reset_counter()
    counter.access_shared_resource("T_Zero", 0)
    print(f"Final counter: {counter.get_current_counter()}\\n")
    
    print("Test Case 4: Sequential access")
    counter.reset_counter()
    for i in range(3):
        counter.access_shared_resource(f"T_Seq{i}", 10)
    print(f"Final counter: {counter.get_current_counter()}\\n")
    
    print("Test Case 5: Invalid inputs")
    counter.reset_counter()
    counter.access_shared_resource(None, 5)
    counter.access_shared_resource("", 5)
    counter.access_shared_resource("T_Valid", -1)
    print(f"Final counter: {counter.get_current_counter()}")


if __name__ == "__main__":
    main()
