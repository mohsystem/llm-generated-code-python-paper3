
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class LinkedList:
    def __init__(self):
        self.head = None
    
    def insert(self, data):
        """Insert at the end of the list"""
        new_node = Node(data)
        if self.head is None:
            self.head = new_node
            return
        
        current = self.head
        while current.next is not None:
            current = current.next
        current.next = new_node
    
    def delete(self, data):
        """Delete first occurrence of data"""
        if self.head is None:
            return False
        
        if self.head.data == data:
            self.head = self.head.next
            return True
        
        current = self.head
        while current.next is not None:
            if current.next.data == data:
                current.next = current.next.next
                return True
            current = current.next
        return False
    
    def search(self, data):
        """Search for data in the list"""
        current = self.head
        while current is not None:
            if current.data == data:
                return True
            current = current.next
        return False
    
    def display(self):
        """Display the list"""
        current = self.head
        elements = []
        while current is not None:
            elements.append(str(current.data))
            current = current.next
        print(" -> ".join(elements) + " -> None")

if __name__ == "__main__":
    # Test Case 1: Insert and display
    print("Test Case 1: Insert elements")
    list1 = LinkedList()
    list1.insert(10)
    list1.insert(20)
    list1.insert(30)
    list1.display()
    
    # Test Case 2: Search operations
    print("\\nTest Case 2: Search operations")
    list2 = LinkedList()
    list2.insert(5)
    list2.insert(15)
    list2.insert(25)
    print(f"Search 15: {list2.search(15)}")
    print(f"Search 100: {list2.search(100)}")
    
    # Test Case 3: Delete operations
    print("\\nTest Case 3: Delete operations")
    list3 = LinkedList()
    list3.insert(1)
    list3.insert(2)
    list3.insert(3)
    list3.insert(4)
    print("Before delete: ", end="")
    list3.display()
    list3.delete(3)
    print("After deleting 3: ", end="")
    list3.display()
    
    # Test Case 4: Delete head element
    print("\\nTest Case 4: Delete head element")
    list4 = LinkedList()
    list4.insert(100)
    list4.insert(200)
    list4.insert(300)
    print("Before delete: ", end="")
    list4.display()
    list4.delete(100)
    print("After deleting head: ", end="")
    list4.display()
    
    # Test Case 5: Operations on empty list
    print("\\nTest Case 5: Operations on empty list")
    list5 = LinkedList()
    print(f"Delete from empty list: {list5.delete(10)}")
    print(f"Search in empty list: {list5.search(10)}")
    list5.insert(50)
    print("After inserting 50: ", end="")
    list5.display()
