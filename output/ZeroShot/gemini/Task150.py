class Node:
    """Node class for the linked list."""
    def __init__(self, data):
        self.data = data
        self.next = None

class LinkedList:
    """Singly Linked List implementation."""
    def __init__(self):
        self.head = None

    def insert(self, data):
        """Inserts a new node with the given data at the end of the list."""
        new_node = Node(data)
        # If the list is empty, make the new node the head
        if self.head is None:
            self.head = new_node
            return
        # Traverse to the last node
        last = self.head
        while last.next:
            last = last.next
        # Append the new node at the end
        last.next = new_node

    def delete(self, key):
        """Deletes the first occurrence of a node with the given key."""
        temp = self.head
        prev = None

        # Case 1: If the head node itself holds the key to be deleted
        if temp is not None and temp.data == key:
            self.head = temp.next
            return

        # Case 2: Search for the key, keeping track of the previous node
        while temp is not None and temp.data != key:
            prev = temp
            temp = temp.next

        # If the key was not present in the list
        if temp is None:
            return

        # Unlink the node from the list. This check is a safe programming
        # practice, although prev will not be None here due to the head check.
        if prev is not None:
            prev.next = temp.next

    def search(self, key):
        """Searches for a node with the given key in the list."""
        current = self.head
        while current is not None:
            if current.data == key:
                return True  # Key found
            current = current.next
        return False  # Key not found

    def print_list(self):
        """Utility function to print the linked list."""
        current = self.head
        if current is None:
            print("List is empty.")
            return
        
        nodes = []
        while current:
            nodes.append(str(current.data))
            current = current.next
        print(" -> ".join(nodes) + " -> NULL")

def main():
    """Main function with test cases."""
    llist = LinkedList()

    # Test Case 1: Insertion
    print("--- Test Case 1: Insertion ---")
    llist.insert(10)
    llist.insert(20)
    llist.insert(30)
    llist.insert(40)
    print("List after inserting 10, 20, 30, 40: ", end="")
    llist.print_list()
    print()

    # Test Case 2: Search for an existing element
    print("--- Test Case 2: Search (Existing) ---")
    print(f"Searching for 30: {'Found' if llist.search(30) else 'Not Found'}")
    print()

    # Test Case 3: Search for a non-existing element
    print("--- Test Case 3: Search (Non-Existing) ---")
    print(f"Searching for 99: {'Found' if llist.search(99) else 'Not Found'}")
    print()

    # Test Case 4: Delete an element from the middle
    print("--- Test Case 4: Deletion (Middle) ---")
    print("List before deleting 20: ", end="")
    llist.print_list()
    llist.delete(20)
    print("List after deleting 20: ", end="")
    llist.print_list()
    print()

    # Test Case 5: Delete the head element
    print("--- Test Case 5: Deletion (Head) ---")
    print("List before deleting 10: ", end="")
    llist.print_list()
    llist.delete(10)
    print("List after deleting 10: ", end="")
    llist.print_list()

if __name__ == "__main__":
    main()