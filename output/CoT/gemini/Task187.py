import threading
import time

class H2O:
    def __init__(self):
        # Semaphores to allow 2 hydrogens and 1 oxygen to proceed
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        
        # Barrier to wait for all 3 atoms to be ready
        # The action will reset the semaphores for the next molecule
        self.barrier = threading.Barrier(3, self._reset_semaphores)

    def _reset_semaphores(self):
        self.h_sem.release(2)
        self.o_sem.release(1)

    def hydrogen(self, releaseHydrogen):
        """
        :type releaseHydrogen: method
        :rtype: void
        """
        self.h_sem.acquire()
        # releaseHydrogen() outputs "H"
        releaseHydrogen()
        self.barrier.wait()


    def oxygen(self, releaseOxygen):
        """
        :type releaseOxygen: method
        :rtype: void
        """
        self.o_sem.acquire()
        # releaseOxygen() outputs "O"
        releaseOxygen()
        self.barrier.wait()

class Task187:
    @staticmethod
    def run_water_simulation(water: str) -> str:
        h2o = H2O()
        result = []
        lock = threading.Lock()
        
        threads = []

        for atom in water:
            if atom == 'H':
                # Using a default argument to capture the current value of 'atom'
                threads.append(threading.Thread(target=h2o.hydrogen, args=(lambda char='H': result.append(char),)))
            elif atom == 'O':
                threads.append(threading.Thread(target=h2o.oxygen, args=(lambda char='O': result.append(char),)))

        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
            
        return "".join(result)

    @staticmethod
    def main():
        test_cases = [
            "HOH",
            "OOHHHH",
            "HHOHHO",
            "HHHHHHOOO",
            "OHHOHHOHH"
        ]

        for i, test_case in enumerate(test_cases):
            print(f"Test Case {i + 1}:")
            print(f"Input: {test_case}")
            output = Task187.run_water_simulation(test_case)
            print(f"Output: {output}")
            print("--------------------")

if __name__ == "__main__":
    Task187.main()