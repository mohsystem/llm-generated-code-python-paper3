
# INSECURE - For educational purposes only
# WARNING: Never store sensitive data like this in production!

class Task124:
    def __init__(self, credit_card, ssn, name):
        # Insecure: storing sensitive data in plain text
        self.credit_card = credit_card
        self.ssn = ssn
        self.name = name
    
    def __str__(self):
        return f"Name: {self.name}, CC: {self.credit_card}, SSN: {self.ssn}"

def main():
    print("WARNING: This is an INSECURE example for educational purposes only!")
    print("Never store sensitive data in plain text in production systems.\\n")
    
    # Test cases showing insecure storage
    data1 = Task124("4532-1234-5678-9010", "123-45-6789", "John Doe")
    data2 = Task124("5425-2334-3010-9876", "987-65-4321", "Jane Smith")
    data3 = Task124("3782-822463-10005", "555-55-5555", "Bob Johnson")
    data4 = Task124("6011-1111-1111-1117", "222-22-2222", "Alice Williams")
    data5 = Task124("3056-9309-0259-04", "333-33-3333", "Charlie Brown")
    
    print("Insecurely stored data:")
    print(data1)
    print(data2)
    print(data3)
    print(data4)
    print(data5)

if __name__ == "__main__":
    main()
