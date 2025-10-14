
from threading import RLock
from decimal import Decimal, InvalidOperation
from typing import Optional, Dict
import threading


class BankAccount:
    def __init__(self, account_id: str, initial_balance: Decimal):
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            raise ValueError("Account ID cannot be None or empty")
        if initial_balance is None or initial_balance < Decimal('0'):
            raise ValueError("Initial balance cannot be None or negative")
        
        self._account_id: str = account_id
        self._balance: Decimal = initial_balance
        self._closed: bool = False
        self._lock: RLock = RLock()

    def deposit(self, amount: Decimal) -> bool:
        if amount is None or amount <= Decimal('0'):
            return False
        
        with self._lock:
            if self._closed:
                return False
            self._balance += amount
            return True

    def withdraw(self, amount: Decimal) -> bool:
        if amount is None or amount <= Decimal('0'):
            return False
        
        with self._lock:
            if self._closed:
                return False
            if self._balance < amount:
                return False
            self._balance -= amount
            return True

    def get_balance(self) -> Optional[Decimal]:
        with self._lock:
            if self._closed:
                return None
            return self._balance

    def close(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._closed = True
            return True

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def get_account_id(self) -> str:
        return self._account_id


class BankingSystem:
    def __init__(self):
        self._accounts: Dict[str, BankAccount] = {}
        self._accounts_lock: RLock = RLock()

    def open_account(self, account_id: str, initial_balance: Decimal) -> bool:
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            return False
        if initial_balance is None or initial_balance < Decimal('0'):
            return False
        
        with self._accounts_lock:
            if account_id in self._accounts:
                return False
            try:
                new_account = BankAccount(account_id, initial_balance)
                self._accounts[account_id] = new_account
                return True
            except (ValueError, InvalidOperation):
                return False

    def close_account(self, account_id: str) -> bool:
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            return False
        
        with self._accounts_lock:
            account = self._accounts.get(account_id)
            if account is None:
                return False
            return account.close()

    def deposit(self, account_id: str, amount: Decimal) -> bool:
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            return False
        
        with self._accounts_lock:
            account = self._accounts.get(account_id)
            if account is None:
                return False
        
        return account.deposit(amount)

    def withdraw(self, account_id: str, amount: Decimal) -> bool:
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            return False
        
        with self._accounts_lock:
            account = self._accounts.get(account_id)
            if account is None:
                return False
        
        return account.withdraw(amount)

    def get_balance(self, account_id: str) -> Optional[Decimal]:
        if not account_id or not isinstance(account_id, str) or not account_id.strip():
            return None
        
        with self._accounts_lock:
            account = self._accounts.get(account_id)
            if account is None:
                return None
        
        return account.get_balance()


def main():
    bank = BankingSystem()

    print("Test 1: Open account and check balance")
    opened = bank.open_account("ACC001", Decimal("1000.00"))
    balance = bank.get_balance("ACC001")
    print(f"Account opened: {opened}, Balance: {balance}")

    print("\\nTest 2: Deposit money")
    deposited = bank.deposit("ACC001", Decimal("500.00"))
    balance = bank.get_balance("ACC001")
    print(f"Deposit successful: {deposited}, New balance: {balance}")

    print("\\nTest 3: Withdraw money")
    withdrawn = bank.withdraw("ACC001", Decimal("300.00"))
    balance = bank.get_balance("ACC001")
    print(f"Withdrawal successful: {withdrawn}, New balance: {balance}")

    print("\\nTest 4: Close account and try to deposit")
    closed = bank.close_account("ACC001")
    deposit_after_close = bank.deposit("ACC001", Decimal("100.00"))
    print(f"Account closed: {closed}, Deposit after close: {deposit_after_close}")

    print("\\nTest 5: Concurrent operations")
    bank.open_account("ACC002", Decimal("2000.00"))
    
    def deposit_task():
        for _ in range(5):
            bank.deposit("ACC002", Decimal("10.00"))
    
    def withdraw_task():
        for _ in range(5):
            bank.withdraw("ACC002", Decimal("5.00"))
    
    t1 = threading.Thread(target=deposit_task)
    t2 = threading.Thread(target=withdraw_task)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    
    balance = bank.get_balance("ACC002")
    print(f"Final balance after concurrent operations: {balance}")


if __name__ == "__main__":
    main()
