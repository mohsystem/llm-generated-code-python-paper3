import threading
import time

class BankAccount:
    def __init__(self):
        self._balance = 0
        self._is_open = False
        self._lock = threading.Lock()

    def open(self, initial_balance=0):
        with self._lock:
            if initial_balance < 0:
                raise ValueError("Initial balance cannot be negative.")
            if self._is_open:
                raise ValueError("Account is already open.")
            self._balance = initial_balance
            self._is_open = True
            return True
        return False

    def get_balance(self):
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            return self._balance

    def deposit(self, amount):
        if amount <= 0:
            raise ValueError("Deposit amount must be positive.")
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            self._balance += amount
            return self._balance

    def withdraw(self, amount):
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive.")
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is closed.")
            if self._balance < amount:
                raise ValueError("Insufficient funds.")
            self._balance -= amount
            return self._balance

    def close(self):
        with self._lock:
            if not self._is_open:
                raise ValueError("Account is already closed.")
            self._is_open = False
            # Optional: Clear balance on close
            # self._balance = 0 
            return True

class Task181:
    @staticmethod
    def run_tests():
        # Test Case 1: Basic Operations
        print("--- Test Case 1: Basic Operations ---")
        account1 = BankAccount()
        try:
            account1.open(1000)
            print(f"Initial Balance: {account1.get_balance()}")
            account1.deposit(500)
            print(f"Balance after deposit: {account1.get_balance()}")
            account1.withdraw(200)
            print(f"Balance after withdrawal: {account1.get_balance()}")
        except ValueError as e:
            print(f"Error: {e}")

        # Test Case 2: Insufficient Funds
        print("\n--- Test Case 2: Insufficient Funds ---")
        try:
            print(f"Current Balance: {account1.get_balance()}")
            print("Attempting to withdraw 2000...")
            account1.withdraw(2000)
        except ValueError as e:
            print(f"Caught expected error: {e}")

        # Test Case 3: Operations on a closed account
        print("\n--- Test Case 3: Operations on Closed Account ---")
        account1.close()
        print("Account closed.")
        try:
            account1.deposit(100)
        except ValueError as e:
            print(f"Caught expected error on deposit: {e}")
        try:
            account1.withdraw(50)
        except ValueError as e:
            print(f"Caught expected error on withdraw: {e}")
        try:
            account1.get_balance()
        except ValueError as e:
            print(f"Caught expected error on get_balance: {e}")

        # Test Case 4: Concurrent Transactions
        print("\n--- Test Case 4: Concurrent Transactions ---")
        account2 = BankAccount()
        account2.open(10000)
        threads = []
        def depositor():
            for _ in range(1000):
                account2.deposit(10)
        def withdrawer():
            for _ in range(1000):
                account2.withdraw(5)

        for _ in range(5):
            threads.append(threading.Thread(target=depositor))
            threads.append(threading.Thread(target=withdrawer))

        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        print("Initial concurrent balance: 10000")
        print("After 5 threads depositing (1000*10) and 5 threads withdrawing (1000*5)...")
        # Expected: 10000 + 5 * (1000 * 10) - 5 * (1000 * 5) = 10000 + 50000 - 25000 = 35000
        print(f"Final concurrent balance: {account2.get_balance()}")
        
        # Test Case 5: Opening with negative balance
        print("\n--- Test Case 5: Opening with Negative Balance ---")
        account3 = BankAccount()
        try:
            account3.open(-100)
        except ValueError as e:
            print(f"Caught expected error: {e}")

if __name__ == "__main__":
    Task181.run_tests()