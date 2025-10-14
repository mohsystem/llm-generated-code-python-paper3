class Node:
    """A node in a singly linked list."""
    def __init__(self, data):
        self.data = data
        self.next = None

def insert(head, data):
    """Inserts a new node at the beginning of the list."""
    new_node = Node(data)
    new_node.next = head
    return new_node

def delete(head, key):
    """Deletes the first occurrence of a node with the given key."""
    # Security: Handle case where list is empty.
    if head is None:
        return None
    
    # Case 1: The head node itself holds the key to be deleted.
    if head.data == key:
        return head.next # The new head is the next node.

    current = head
    # Case 2: The key is somewhere other than the head.
    # Traverse the list to find the node *before* the one to be deleted.
    # Security: Check for current.next is not None to prevent attribute error.
    while current.next is not None and current.next.data != key:
        current = current.next
        
    # If the key was found (current.next is the node to delete).
    if current.next is not None:
        current.next = current.next.next # Unlink the node.
        
    return head

def search(head, key):
    """Searches for a node with the given key."""
    current = head
    # Security: Loop condition prevents trying to access 'data' on None.
    while current is not None:
        if current.data == key:
            return True
        current = current.next
    return False

def print_list(head):
    """Utility function to print the linked list."""
    current = head
    while current:
        print(f"{current.data} -> ", end="")
        current = current.next
    print("None")

def main():
    """Main function with test cases."""
    head = None

    # Test Case 1: Insertion
    print("Test Case 1: Insertion")
    head = insert(head, 30)
    head = insert(head, 20)
    head = insert(head, 10)
    print("List after insertions: ", end="")
    print_list(head)  # Expected: 10 -> 20 -> 30 -> None
    print("--------------------")

    # Test Case 2: Search for an existing element
    print("Test Case 2: Search for existing element (20)")
    print(f"Found: {search(head, 20)}")  # Expected: True
    print("--------------------")

    # Test Case 3: Search for a non-existent element
    print("Test Case 3: Search for non-existent element (50)")
    print(f"Found: {search(head, 50)}")  # Expected: False
    print("--------------------")

    # Test Case 4: Delete an element from the middle
    print("Test Case 4: Delete middle element (20)")
    head = delete(head, 20)
    print("List after deleting 20: ", end="")
    print_list(head)  # Expected: 10 -> 30 -> None
    print("--------------------")

    # Test Case 5: Delete head, non-existent, and from empty list
    print("Test Case 5: Complex Deletions")
    head = delete(head, 10) # Delete head
    print("List after deleting head (10): ", end="")
    print_list(head)  # Expected: 30 -> None
    head = delete(head, 100) # Delete non-existent
    print("List after attempting to delete 100: ", end="")
    print_list(head)  # Expected: 30 -> None
    head = delete(head, 30) # Delete last element
    print("List after deleting 30: ", end="")
    print_list(head)  # Expected: None
    head = delete(head, 5)  # Delete from empty list
    print("List after deleting from empty list: ", end="")
    print_list(head) # Expected: None
    print("--------------------")
    
if __name__ == "__main__":
    main()