
import threading
from typing import Dict, Optional

class Task181:
    class BankAccount:
        def __init__(self, initial_balance: float):
            self.balance = initial_balance
            self.closed = False
            self.lock = threading.RLock()

        def deposit(self, amount: float) -> bool:
            with self.lock:
                if self.closed or amount <= 0:
                    return False
                self.balance += amount
                return True

        def withdraw(self, amount: float) -> bool:
            with self.lock:
                if self.closed or amount <= 0 or amount > self.balance:
                    return False
                self.balance -= amount
                return True

        def get_balance(self) -> float:
            with self.lock:
                if self.closed:
                    return -1
                return self.balance

        def close(self) -> bool:
            with self.lock:
                if self.closed:
                    return False
                self.closed = True
                return True

        def is_closed(self) -> bool:
            with self.lock:
                return self.closed

    def __init__(self):
        self.accounts: Dict[str, Task181.BankAccount] = {}
        self.accounts_lock = threading.RLock()

    def open_account(self, account_id: str, initial_balance: float) -> bool:
        if account_id is None or initial_balance < 0:
            return False
        
        with self.accounts_lock:
            if account_id in self.accounts:
                return False
            self.accounts[account_id] = Task181.BankAccount(initial_balance)
            return True

    def close_account(self, account_id: str) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
            return account.close()

    def deposit(self, account_id: str, amount: float) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
        return account.deposit(amount)

    def withdraw(self, account_id: str, amount: float) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
        return account.withdraw(amount)

    def get_balance(self, account_id: str) -> float:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return -1
        return account.get_balance()


if __name__ == "__main__":
    bank = Task181()

    # Test Case 1: Open account and deposit
    print("Test Case 1: Open account and deposit")
    bank.open_account("ACC001", 1000.0)
    bank.deposit("ACC001", 500.0)
    print(f"Balance: {bank.get_balance('ACC001')}")  # Expected: 1500.0

    # Test Case 2: Withdraw from account
    print("\\nTest Case 2: Withdraw from account")
    bank.withdraw("ACC001", 300.0)
    print(f"Balance: {bank.get_balance('ACC001')}")  # Expected: 1200.0

    # Test Case 3: Close account and try operations
    print("\\nTest Case 3: Close account and try operations")
    bank.close_account("ACC001")
    print(f"Deposit after close: {bank.deposit('ACC001', 100.0)}")  # Expected: False
    print(f"Balance after close: {bank.get_balance('ACC001')}")  # Expected: -1

    # Test Case 4: Concurrent operations
    print("\\nTest Case 4: Concurrent operations")
    bank.open_account("ACC002", 5000.0)
    
    def deposit_ops():
        for _ in range(100):
            bank.deposit("ACC002", 10.0)
    
    def withdraw_ops():
        for _ in range(100):
            bank.withdraw("ACC002", 5.0)
    
    t1 = threading.Thread(target=deposit_ops)
    t2 = threading.Thread(target=withdraw_ops)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print(f"Balance after concurrent ops: {bank.get_balance('ACC002')}")  # Expected: 5500.0

    # Test Case 5: Invalid operations
    print("\\nTest Case 5: Invalid operations")
    print(f"Open duplicate account: {bank.open_account('ACC002', 1000.0)}")  # Expected: False
    print(f"Withdraw from non-existent: {bank.withdraw('ACC999', 100.0)}")  # Expected: False
    print(f"Overdraw: {bank.withdraw('ACC002', 10000.0)}")  # Expected: False
