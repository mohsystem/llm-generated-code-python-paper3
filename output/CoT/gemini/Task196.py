import threading

class ZeroEvenOdd:
    def __init__(self, n):
        self.n = n
        self.turn = 0  # 0 for zero, 1 for odd, 2 for even
        self.cond = threading.Condition()

    def zero(self, printNumber):
        for i in range(1, self.n + 1):
            with self.cond:
                self.cond.wait_for(lambda: self.turn == 0)
                printNumber(0)
                if i % 2 != 0:
                    self.turn = 1
                else:
                    self.turn = 2
                self.cond.notify_all()

    def even(self, printNumber):
        for i in range(2, self.n + 1, 2):
            with self.cond:
                self.cond.wait_for(lambda: self.turn == 2)
                printNumber(i)
                self.turn = 0
                self.cond.notify_all()

    def odd(self, printNumber):
        for i in range(1, self.n + 1, 2):
            with self.cond:
                self.cond.wait_for(lambda: self.turn == 1)
                printNumber(i)
                self.turn = 0
                self.cond.notify_all()

def run_test(n):
    print(f"Test Case for n = {n}")
    print("Output: ", end="")
    
    zero_even_odd = ZeroEvenOdd(n)
    print_number = lambda x: print(x, end="")
    
    thread_a = threading.Thread(target=zero_even_odd.zero, args=(print_number,))
    thread_b = threading.Thread(target=zero_even_odd.even, args=(print_number,))
    thread_c = threading.Thread(target=zero_even_odd.odd, args=(print_number,))
    
    thread_a.start()
    thread_b.start()
    thread_c.start()
    
    thread_a.join()
    thread_b.join()
    thread_c.join()
    
    print("\n")

if __name__ == "__main__":
    run_test(2)
    run_test(5)
    run_test(1)
    run_test(6)
    run_test(10)