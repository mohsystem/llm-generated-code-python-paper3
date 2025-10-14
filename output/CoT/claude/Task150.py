
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class LinkedList:
    def __init__(self):
        self.head = None
    
    def insert(self, data):
        """Insert at the beginning"""
        new_node = Node(data)
        new_node.next = self.head
        self.head = new_node
    
    def insert_at_end(self, data):
        """Insert at the end"""
        new_node = Node(data)
        if self.head is None:
            self.head = new_node
            return
        
        current = self.head
        while current.next is not None:
            current = current.next
        current.next = new_node
    
    def delete(self, data):
        """Delete first occurrence of a value"""
        if self.head is None:
            return False
        
        # Delete head node
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
        """Search for a value"""
        current = self.head
        while current is not None:
            if current.data == data:
                return True
            current = current.next
        return False
    
    def display(self):
        """Display the list"""
        if self.head is None:
            print("List is empty")
            return
        
        current = self.head
        while current is not None:
            print(current.data, end=" -> ")
            current = current.next
        print("None")

def main():
    print("Test Case 1: Insert at beginning and display")
    list1 = LinkedList()
    list1.insert(10)
    list1.insert(20)
    list1.insert(30)
    list1.display()
    
    print("\\nTest Case 2: Search operations")
    list2 = LinkedList()
    list2.insert(5)
    list2.insert(15)
    list2.insert(25)
    print(f"Search 15: {list2.search(15)}")
    print(f"Search 100: {list2.search(100)}")
    
    print("\\nTest Case 3: Delete operations")
    list3 = LinkedList()
    list3.insert(1)
    list3.insert(2)
    list3.insert(3)
    list3.insert(4)
    print("Before delete:")
    list3.display()
    list3.delete(3)
    print("After deleting 3:")
    list3.display()
    
    print("\\nTest Case 4: Insert at end")
    list4 = LinkedList()
    list4.insert_at_end(100)
    list4.insert_at_end(200)
    list4.insert_at_end(300)
    list4.display()
    
    print("\\nTest Case 5: Operations on empty list")
    list5 = LinkedList()
    print(f"Search in empty list: {list5.search(10)}")
    print(f"Delete from empty list: {list5.delete(10)}")
    list5.display()

if __name__ == "__main__":
    main()
