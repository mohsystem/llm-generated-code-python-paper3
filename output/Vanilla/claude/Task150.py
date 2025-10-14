
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
        else:
            current = self.head
            while current.next is not None:
                current = current.next
            current.next = new_node
    
    def delete(self, data):
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
        current = self.head
        while current is not None:
            if current.data == data:
                return True
            current = current.next
        return False
    
    def display(self):
        current = self.head
        result = []
        while current is not None:
            result.append(str(current.data))
            current = current.next
        print("[" + ", ".join(result) + "]")

if __name__ == "__main__":
    # Test Case 1: Basic insert and search
    print("Test Case 1: Basic insert and search")
    list1 = LinkedList()
    list1.insert(10)
    list1.insert(20)
    list1.insert(30)
    list1.display()
    print(f"Search 20: {list1.search(20)}")
    print(f"Search 40: {list1.search(40)}")
    print()
    
    # Test Case 2: Delete from middle
    print("Test Case 2: Delete from middle")
    list2 = LinkedList()
    list2.insert(5)
    list2.insert(15)
    list2.insert(25)
    list2.insert(35)
    print("Before delete: ", end="")
    list2.display()
    list2.delete(15)
    print("After delete 15: ", end="")
    list2.display()
    print()
    
    # Test Case 3: Delete head
    print("Test Case 3: Delete head")
    list3 = LinkedList()
    list3.insert(100)
    list3.insert(200)
    list3.insert(300)
    print("Before delete: ", end="")
    list3.display()
    list3.delete(100)
    print("After delete head: ", end="")
    list3.display()
    print()
    
    # Test Case 4: Delete non-existent element
    print("Test Case 4: Delete non-existent element")
    list4 = LinkedList()
    list4.insert(1)
    list4.insert(2)
    list4.insert(3)
    print("List: ", end="")
    list4.display()
    print(f"Delete 99: {list4.delete(99)}")
    print()
    
    # Test Case 5: Operations on empty list
    print("Test Case 5: Operations on empty list")
    list5 = LinkedList()
    print(f"Search in empty list: {list5.search(10)}")
    print(f"Delete from empty list: {list5.delete(10)}")
    list5.insert(50)
    print("After insert: ", end="")
    list5.display()
