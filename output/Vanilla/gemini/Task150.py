class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class LinkedList:
    def __init__(self):
        self.head = None

    def insert(self, data):
        new_node = Node(data)
        if self.head is None:
            self.head = new_node
            return
        last = self.head
        while last.next:
            last = last.next
        last.next = new_node

    def delete(self, key):
        temp = self.head
        
        # If head node itself holds the key to be deleted
        if temp is not None:
            if temp.data == key:
                self.head = temp.next
                temp = None
                return

        # Search for the key to be deleted, keep track of the previous node
        prev = None
        while temp is not None:
            if temp.data == key:
                break
            prev = temp
            temp = temp.next

        # if key was not present in linked list
        if temp is None:
            return

        # Unlink the node from linked list
        prev.next = temp.next
        temp = None
        
    def search(self, key):
        current = self.head
        while current is not None:
            if current.data == key:
                return True
            current = current.next
        return False

    def print_list(self):
        current = self.head
        while current:
            print(f"{current.data} -> ", end="")
            current = current.next
        print("NULL")

if __name__ == '__main__':
    llist = LinkedList()

    # Test Case 1: Insertion
    print("--- Test Case 1: Insertion ---")
    llist.insert(10)
    llist.insert(20)
    llist.insert(30)
    llist.insert(40)
    llist.insert(50)
    print("Created Linked list: ", end="")
    llist.print_list()
    print()

    # Test Case 2: Search for an existing element
    print("--- Test Case 2: Search (Existing) ---")
    print("Searching for 30...")
    if llist.search(30):
        print("Element 30 found in the list.")
    else:
        print("Element 30 not found in the list.")
    print()

    # Test Case 3: Search for a non-existing element
    print("--- Test Case 3: Search (Not Existing) ---")
    print("Searching for 100...")
    if llist.search(100):
        print("Element 100 found in the list.")
    else:
        print("Element 100 not found in the list.")
    print()

    # Test Case 4: Deletion of a middle element
    print("--- Test Case 4: Deletion (Middle) ---")
    print("Deleting element 30...")
    llist.delete(30)
    print("List after deleting 30: ", end="")
    llist.print_list()
    print()

    # Test Case 5: Deletion of head and tail elements
    print("--- Test Case 5: Deletion (Head and Tail) ---")
    print("Deleting element 10 (head)...")
    llist.delete(10)
    print("List after deleting 10: ", end="")
    llist.print_list()
    
    print("Deleting element 50 (tail)...")
    llist.delete(50)
    print("List after deleting 50: ", end="")
    llist.print_list()