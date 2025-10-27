# Step 1: Define Person with a status field.
class Person:
    def __init__(self):
        # Step 3: Secure initialization.
        self.status = 0

# Step 3: Secure allocation method to create a new Person and set status to 0.
def allocate_person():
    p = Person()
    # Explicitly ensure status is 0.
    p.status = 0
    return p

# Step 5: Main with 5 test cases.
def main():
    cases = [allocate_person() for _ in range(5)]
    for i, p in enumerate(cases, 1):
        print(f"Test{i} status: {p.status}")

if __name__ == "__main__":
    main()