
import threading
from typing import Dict, Optional

class Task181:
    class BankAccount:
        def __init__(self, account_id: str, initial_balance: int):
            if initial_balance < 0:
                raise ValueError("Initial balance cannot be negative")
            self.account_id = account_id
            self.balance = initial_balance
            self.is_closed = False
            self.lock = threading.RLock()

        def deposit(self, amount: int) -> bool:
            if amount <= 0:
                return False
            
            with self.lock:
                if self.is_closed:
                    return False
                # Check for overflow (Python handles big integers, but we simulate bounds)
                if self.balance > (2**63 - 1) - amount:
                    return False
                self.balance += amount
                return True

        def withdraw(self, amount: int) -> bool:
            if amount <= 0:
                return False
            
            with self.lock:
                if self.is_closed:
                    return False
                if self.balance < amount:
                    return False
                self.balance -= amount
                return True

        def get_balance(self) -> int:
            with self.lock:
                return -1 if self.is_closed else self.balance

        def close(self) -> bool:
            with self.lock:
                if self.is_closed:
                    return False
                self.is_closed = True
                return True

        def is_open(self) -> bool:
            with self.lock:
                return not self.is_closed

    class BankingSystem:
        def __init__(self):
            self.accounts: Dict[str, 'Task181.BankAccount'] = {}
            self.accounts_lock = threading.Lock()

        def open_account(self, account_id: str, initial_balance: int) -> bool:
            if not account_id or not account_id.strip():
                return False
            
            with self.accounts_lock:
                if account_id in self.accounts:
                    return False
                try:
                    self.accounts[account_id] = Task181.BankAccount(account_id, initial_balance)
                    return True
                except ValueError:
                    return False

        def close_account(self, account_id: str) -> bool:
            account = self.accounts.get(account_id)
            return account is not None and account.close()

        def deposit(self, account_id: str, amount: int) -> bool:
            account = self.accounts.get(account_id)
            return account is not None and account.deposit(amount)

        def withdraw(self, account_id: str, amount: int) -> bool:
            account = self.accounts.get(account_id)
            return account is not None and account.withdraw(amount)

        def get_balance(self, account_id: str) -> int:
            account = self.accounts.get(account_id)
            return account.get_balance() if account is not None else -1

    @staticmethod
    def main():
        bank = Task181.BankingSystem()

        # Test Case 1: Open account and deposit
        print("Test 1 - Open account and deposit:")
        bank.open_account("ACC001", 1000)
        bank.deposit("ACC001", 500)
        print(f"Balance: {bank.get_balance('ACC001')}")  # Expected: 1500

        # Test Case 2: Withdraw from account
        print("\\nTest 2 - Withdraw:")
        bank.withdraw("ACC001", 300)
        print(f"Balance: {bank.get_balance('ACC001')}")  # Expected: 1200

        # Test Case 3: Close account and try operations
        print("\\nTest 3 - Close account:")
        bank.close_account("ACC001")
        deposit_result = bank.deposit("ACC001", 100)
        print(f"Deposit after close: {deposit_result}")  # Expected: False
        print(f"Balance after close: {bank.get_balance('ACC001')}")  # Expected: -1

        # Test Case 4: Insufficient funds
        print("\\nTest 4 - Insufficient funds:")
        bank.open_account("ACC002", 100)
        withdraw_result = bank.withdraw("ACC002", 200)
        print(f"Withdraw result: {withdraw_result}")  # Expected: False

        # Test Case 5: Concurrent operations
        print("\\nTest 5 - Concurrent operations:")
        bank.open_account("ACC003", 1000)
        
        def deposit_task():
            for _ in range(100):
                bank.deposit("ACC003", 10)
        
        def withdraw_task():
            for _ in range(100):
                bank.withdraw("ACC003", 5)
        
        t1 = threading.Thread(target=deposit_task)
        t2 = threading.Thread(target=withdraw_task)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print(f"Final balance: {bank.get_balance('ACC003')}")  # Expected: 1500

if __name__ == "__main__":
    Task181.main()
