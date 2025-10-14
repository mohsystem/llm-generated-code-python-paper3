import typing

class Node:
    """A node in a singly linked list."""
    def __init__(self, data: int):
        self.data: int = data
        self.next: typing.Optional['Node'] = None

class SinglyLinkedList:
    """Singly Linked List implementation."""
    def __init__(self) -> None:
        self.head: typing.Optional[Node] = None

    def insert(self, data: int) -> None:
        """Inserts a new node at the beginning of the list."""
        new_node = Node(data)
        new_node.next = self.head
        self.head = new_node

    def delete(self, key: int) -> None:
        """Deletes the first occurrence of a node with the given key."""
        temp = self.head
        prev: typing.Optional[Node] = None

        # If the head node itself holds the key
        if temp is not None and temp.data == key:
            self.head = temp.next
            return

        # Search for the key, keeping track of the previous node
        while temp is not None and temp.data != key:
            prev = temp
            temp = temp.next

        # If the key was not present in the list
        if temp is None:
            return
        
        # Unlink the node
        if prev is not None:
            prev.next = temp.next

    def search(self, key: int) -> bool:
        """Searches for a node with the given key."""
        current = self.head
        while current is not None:
            if current.data == key:
                return True
            current = current.next
        return False

    def print_list(self) -> None:
        """Prints the linked list."""
        current = self.head
        print_str = ""
        while current:
            print_str += f"{current.data} -> "
            current = current.next
        print_str += "NULL"
        print(print_str)

def main() -> None:
    """Main function with test cases."""
    sll = SinglyLinkedList()

    # Test Case 1: Insertion
    print("--- Test Case 1: Insertion ---")
    sll.insert(3)
    sll.insert(2)
    sll.insert(1)
    print("Created list: ", end="")
    sll.print_list()
    print()

    # Test Case 2: Search for an existing element
    print("--- Test Case 2: Search (existing) ---")
    key_to_search1 = 2
    result1 = "Found" if sll.search(key_to_search1) else "Not Found"
    print(f"Searching for {key_to_search1}: {result1}")
    print()

    # Test Case 3: Search for a non-existing element
    print("--- Test Case 3: Search (non-existing) ---")
    key_to_search2 = 4
    result2 = "Found" if sll.search(key_to_search2) else "Not Found"
    print(f"Searching for {key_to_search2}: {result2}")
    print()

    # Test Case 4: Delete an element from the middle
    print("--- Test Case 4: Deletion (middle) ---")
    key_to_delete1 = 2
    print(f"Deleting {key_to_delete1}")
    sll.delete(key_to_delete1)
    print("List after deletion: ", end="")
    sll.print_list()
    print()

    # Test Case 5: Delete the head element
    print("--- Test Case 5: Deletion (head) ---")
    key_to_delete2 = 1
    print(f"Deleting {key_to_delete2}")
    sll.delete(key_to_delete2)
    print("List after deletion: ", end="")
    sll.print_list()

if __name__ == "__main__":
    main()