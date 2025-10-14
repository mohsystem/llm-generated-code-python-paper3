import threading
import time

class BankAccount:
    def __init__(self):
        self._balance = 0
        self._is_open = False
        self._lock = threading.Lock()

    def open(self, initial_deposit=0):
        with self._lock:
            # if self._is_open:
            #     raise ValueError("Account is already open.")
            if initial_deposit < 0:
                raise ValueError("Initial deposit cannot be negative.")
            self._balance = initial_deposit
            self._is_open = True

    def close(self):
        with self._lock:
            self._is_open = False

    def get_balance(self):
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            return self._balance

    def deposit(self, amount):
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            if amount <= 0:
                raise ValueError("Deposit amount must be positive.")
            self._balance += amount

    def withdraw(self, amount):
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            if amount <= 0:
                raise ValueError("Withdrawal amount must be positive.")
            if self._balance < amount:
                raise ValueError("Insufficient funds.")
            self._balance -= amount

def main():
    print("--- Python Bank Account Tests ---")

    # Test Case 1: Simple Deposit/Withdraw
    print("\n--- Test Case 1: Simple Transactions ---")
    try:
        acc1 = BankAccount()
        acc1.open(100)
        print(f"Opened with balance: {acc1.get_balance()}")
        acc1.deposit(50)
        print(f"After deposit of 50, balance: {acc1.get_balance()}")
        acc1.withdraw(30)
        print(f"After withdrawal of 30, balance: {acc1.get_balance()}")
        if acc1.get_balance() == 120:
            print("Test Case 1 PASSED")
        else:
            print("Test Case 1 FAILED")

        # Test Case 2: Insufficient Funds
        print("\n--- Test Case 2: Insufficient Funds ---")
        try:
            print(f"Attempting to withdraw 200 from {acc1.get_balance()}...")
            acc1.withdraw(200)
            print("Test Case 2 FAILED")
        except ValueError as e:
            print(f"Caught expected exception: {e}")
            print("Test Case 2 PASSED")

        # Test Case 3: Closed Account Operations
        print("\n--- Test Case 3: Closed Account ---")
        acc1.close()
        print("Account closed.")
        try:
            acc1.get_balance()
            print("Test Case 3 FAILED (getBalance on closed account)")
        except ValueError as e:
            print(f"Caught expected exception on getBalance: {e}")
            print("Test Case 3 PASSED")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


    # Test Case 4: Concurrent Transactions
    print("\n--- Test Case 4: Concurrent Transactions ---")
    try:
        shared_account = BankAccount()
        shared_account.open(10000)
        transactions = 1000
        num_thread_pairs = 10

        def worker(account, is_depositor):
            for _ in range(transactions):
                if is_depositor:
                    account.deposit(10)
                else:
                    account.withdraw(10)

        threads = []
        for _ in range(num_thread_pairs):
            threads.append(threading.Thread(target=worker, args=(shared_account, True)))
            threads.append(threading.Thread(target=worker, args=(shared_account, False)))

        for t in threads: t.start()
        for t in threads: t.join()

        final_balance = shared_account.get_balance()
        print(f"Initial Balance: 10000")
        print(f"Final Balance after concurrent transactions: {final_balance}")
        if final_balance == 10000:
            print("Test Case 4 PASSED")
        else:
            print("Test Case 4 FAILED")
    except Exception as e:
        print(f"An unexpected error occurred in concurrency test: {e}")

    # Test Case 5: Zero/Negative Amount
    print("\n--- Test Case 5: Invalid Amount ---")
    try:
        acc5 = BankAccount()
        acc5.open(100)
        try:
            print("Attempting to deposit -50...")
            acc5.deposit(-50)
            print("Test Case 5 FAILED (negative deposit)")
        except ValueError as e:
            print(f"Caught expected exception: {e}")
        try:
            print("Attempting to withdraw 0...")
            acc5.withdraw(0)
            print("Test Case 5 FAILED (zero withdrawal)")
        except ValueError as e:
            print(f"Caught expected exception: {e}")
            print("Test Case 5 PASSED")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()