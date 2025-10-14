
from threading import RLock
from decimal import Decimal
from typing import Optional, Dict

class Task181:
    class Account:
        def __init__(self, initial_balance: Decimal):
            self.balance = initial_balance
            self.closed = False
            self.lock = RLock()
        
        def deposit(self, amount: Decimal) -> bool:
            with self.lock:
                if self.closed:
                    return False
                if amount <= Decimal('0'):
                    return False
                self.balance += amount
                return True
        
        def withdraw(self, amount: Decimal) -> bool:
            with self.lock:
                if self.closed:
                    return False
                if amount <= Decimal('0'):
                    return False
                if self.balance < amount:
                    return False
                self.balance -= amount
                return True
        
        def get_balance(self) -> Optional[Decimal]:
            with self.lock:
                if self.closed:
                    return None
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
        self.accounts: Dict[str, Task181.Account] = {}
        self.accounts_lock = RLock()
    
    def open_account(self, account_id: str, initial_balance: Decimal) -> bool:
        if account_id is None or initial_balance is None or initial_balance < Decimal('0'):
            return False
        
        with self.accounts_lock:
            if account_id in self.accounts:
                return False
            self.accounts[account_id] = Task181.Account(initial_balance)
            return True
    
    def close_account(self, account_id: str) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
            return account.close()
    
    def deposit(self, account_id: str, amount: Decimal) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
        return account.deposit(amount)
    
    def withdraw(self, account_id: str, amount: Decimal) -> bool:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return False
        return account.withdraw(amount)
    
    def get_balance(self, account_id: str) -> Optional[Decimal]:
        with self.accounts_lock:
            account = self.accounts.get(account_id)
            if account is None:
                return None
        return account.get_balance()


if __name__ == "__main__":
    bank = Task181()
    
    # Test Case 1: Open account and check balance
    print("Test 1: Open account")
    opened = bank.open_account("ACC001", Decimal("1000.00"))
    print(f"Account opened: {opened}")
    print(f"Balance: {bank.get_balance('ACC001')}")
    
    # Test Case 2: Deposit money
    print("\\nTest 2: Deposit money")
    deposited = bank.deposit("ACC001", Decimal("500.00"))
    print(f"Deposit successful: {deposited}")
    print(f"Balance: {bank.get_balance('ACC001')}")
    
    # Test Case 3: Withdraw money
    print("\\nTest 3: Withdraw money")
    withdrawn = bank.withdraw("ACC001", Decimal("300.00"))
    print(f"Withdrawal successful: {withdrawn}")
    print(f"Balance: {bank.get_balance('ACC001')}")
    
    # Test Case 4: Close account and try operations
    print("\\nTest 4: Close account")
    closed = bank.close_account("ACC001")
    print(f"Account closed: {closed}")
    deposit_after_close = bank.deposit("ACC001", Decimal("100.00"))
    print(f"Deposit after close: {deposit_after_close}")
    balance_after_close = bank.get_balance("ACC001")
    print(f"Balance after close: {balance_after_close}")
    
    # Test Case 5: Insufficient funds
    print("\\nTest 5: Insufficient funds")
    bank.open_account("ACC002", Decimal("100.00"))
    withdraw_more = bank.withdraw("ACC002", Decimal("200.00"))
    print(f"Withdrawal (insufficient funds): {withdraw_more}")
    print(f"Balance: {bank.get_balance('ACC002')}")
