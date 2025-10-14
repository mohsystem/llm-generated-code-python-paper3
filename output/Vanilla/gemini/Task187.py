import threading

class H2O:
    def __init__(self):
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        # The barrier action resets the semaphores for the next molecule.
        self.barrier = threading.Barrier(3, action=self._reset_sems)

    def _reset_sems(self):
        self.h_sem.release(2)
        self.o_sem.release(1)

    def hydrogen(self, releaseHydrogen):
        """
        :type releaseHydrogen: method
        :rtype: void
        """
        self.h_sem.acquire()
        self.barrier.wait()
        # releaseHydrogen() outputs "H". Do not change or remove this line.
        releaseHydrogen()

    def oxygen(self, releaseOxygen):
        """
        :type releaseOxygen: method
        :rtype: void
        """
        self.o_sem.acquire()
        self.barrier.wait()
        # releaseOxygen() outputs "O". Do not change or remove this line.
        releaseOxygen()

class Task187:
    @staticmethod
    def run_test(input_str):
        h2o = H2O()
        result = []
        lock = threading.Lock()

        def release_h():
            with lock:
                result.append('H')

        def release_o():
            with lock:
                result.append('O')

        threads = []
        for char in input_str:
            if char == 'H':
                threads.append(threading.Thread(target=h2o.hydrogen, args=(release_h,)))
            elif char == 'O':
                threads.append(threading.Thread(target=h2o.oxygen, args=(release_o,)))

        for t in threads:
            t.start()

        for t in threads:
            t.join()
            
        print(f"Input: {input_str}")
        print(f"Output: {''.join(result)}")
        print("---")


if __name__ == "__main__":
    test_cases = [
        "HOH",
        "OOHHHH",
        "HHHHHHOOO",
        "HOHOHH",
        "OOOHHHHHH"
    ]

    for test_case in test_cases:
        Task187.run_test(test_case)