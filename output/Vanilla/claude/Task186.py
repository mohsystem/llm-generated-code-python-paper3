
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

class Task186:
    def mergeKLists(self, lists):
        if not lists:
            return None
        
        return self.mergeKListsHelper(lists, 0, len(lists) - 1)
    
    def mergeKListsHelper(self, lists, left, right):
        if left == right:
            return lists[left]
        
        if left < right:
            mid = left + (right - left) // 2
            l1 = self.mergeKListsHelper(lists, left, mid)
            l2 = self.mergeKListsHelper(lists, mid + 1, right)
            return self.mergeTwoLists(l1, l2)
        
        return None
    
    def mergeTwoLists(self, l1, l2):
        dummy = ListNode(0)
        current = dummy
        
        while l1 and l2:
            if l1.val <= l2.val:
                current.next = l1
                l1 = l1.next
            else:
                current.next = l2
                l2 = l2.next
            current = current.next
        
        if l1:
            current.next = l1
        if l2:
            current.next = l2
        
        return dummy.next

def createList(arr):
    if not arr:
        return None
    dummy = ListNode(0)
    current = dummy
    for val in arr:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

def printList(head):
    result = []
    while head:
        result.append(str(head.val))
        head = head.next
    print("[" + ",".join(result) + "]")

if __name__ == "__main__":
    solution = Task186()
    
    # Test case 1
    lists1 = [
        createList([1, 4, 5]),
        createList([1, 3, 4]),
        createList([2, 6])
    ]
    print("Test 1: ", end="")
    printList(solution.mergeKLists(lists1))
    
    # Test case 2
    lists2 = []
    print("Test 2: ", end="")
    printList(solution.mergeKLists(lists2))
    
    # Test case 3
    lists3 = [None]
    print("Test 3: ", end="")
    printList(solution.mergeKLists(lists3))
    
    # Test case 4
    lists4 = [
        createList([1, 2, 3]),
        createList([4, 5, 6])
    ]
    print("Test 4: ", end="")
    printList(solution.mergeKLists(lists4))
    
    # Test case 5
    lists5 = [
        createList([-2, -1, 0]),
        createList([-3]),
        createList([1, 2])
    ]
    print("Test 5: ", end="")
    printList(solution.mergeKLists(lists5))
