
import threading

class Task92:
    def __init__(self):
        self.current_counter = 0
        self.max_counter = 10
        self.lock = threading.Lock()

    def access_shared_resource(self, thread_name):
        if self.current_counter <= self.max_counter:
            self.lock.acquire()
            try:
                # Double-check after acquiring lock
                if self.current_counter <= self.max_counter:
                    self.current_counter += 1
                    print(f"{thread_name} is accessing currentCounter: {self.current_counter}")
            finally:
                self.lock.release()


def main():
    # Test Case 1: Multiple threads with counter limit 10
    print("Test Case 1: maxCounter = 10")
    task1 = Task92()
    task1.max_counter = 10
    threads1 = []
    for i in range(5):
        thread_name = f"Thread-{i + 1}"
        t = threading.Thread(target=lambda name=thread_name: [task1.access_shared_resource(name) for _ in range(3)])
        threads1.append(t)
        t.start()
    for t in threads1:
        t.join()

    # Test Case 2: Counter limit 5
    print("\\nTest Case 2: maxCounter = 5")
    task2 = Task92()
    task2.max_counter = 5
    threads2 = []
    for i in range(3):
        thread_name = f"Thread-{i + 1}"
        t = threading.Thread(target=lambda name=thread_name: [task2.access_shared_resource(name) for _ in range(2)])
        threads2.append(t)
        t.start()
    for t in threads2:
        t.join()

    # Test Case 3: Counter limit 0
    print("\\nTest Case 3: maxCounter = 0")
    task3 = Task92()
    task3.max_counter = 0
    t3 = threading.Thread(target=lambda: task3.access_shared_resource("Thread-1"))
    t3.start()
    t3.join()

    # Test Case 4: Counter limit 20
    print("\\nTest Case 4: maxCounter = 20")
    task4 = Task92()
    task4.max_counter = 20
    threads4 = []
    for i in range(10):
        thread_name = f"Thread-{i + 1}"
        t = threading.Thread(target=lambda name=thread_name: [task4.access_shared_resource(name) for _ in range(2)])
        threads4.append(t)
        t.start()
    for t in threads4:
        t.join()

    # Test Case 5: Single thread with counter limit 3
    print("\\nTest Case 5: Single thread, maxCounter = 3")
    task5 = Task92()
    task5.max_counter = 3
    t5 = threading.Thread(target=lambda: [task5.access_shared_resource("Thread-Single") for _ in range(5)])
    t5.start()
    t5.join()


if __name__ == "__main__":
    main()
