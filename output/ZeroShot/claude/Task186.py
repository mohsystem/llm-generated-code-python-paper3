
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

def mergeKLists(lists):
    if not lists or len(lists) == 0:
        return None
    
    return mergeKListsHelper(lists, 0, len(lists) - 1)

def mergeKListsHelper(lists, left, right):
    if left == right:
        return lists[left]
    
    if left > right:
        return None
    
    mid = left + (right - left) // 2
    l1 = mergeKListsHelper(lists, left, mid)
    l2 = mergeKListsHelper(lists, mid + 1, right)
    
    return mergeTwoLists(l1, l2)

def mergeTwoLists(l1, l2):
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
    
    current.next = l1 if l1 else l2
    
    return dummy.next

def createList(arr):
    if not arr:
        return None
    head = ListNode(arr[0])
    current = head
    for i in range(1, len(arr)):
        current.next = ListNode(arr[i])
        current = current.next
    return head

def printList(head):
    result = []
    while head:
        result.append(str(head.val))
        head = head.next
    print("[" + ",".join(result) + "]")

if __name__ == "__main__":
    # Test case 1
    lists1 = [createList([1, 4, 5]), createList([1, 3, 4]), createList([2, 6])]
    print("Test 1: ", end="")
    printList(mergeKLists(lists1))
    
    # Test case 2
    lists2 = []
    print("Test 2: ", end="")
    printList(mergeKLists(lists2))
    
    # Test case 3
    lists3 = [None]
    print("Test 3: ", end="")
    printList(mergeKLists(lists3))
    
    # Test case 4
    lists4 = [createList([1, 2, 3]), createList([4, 5, 6])]
    print("Test 4: ", end="")
    printList(mergeKLists(lists4))
    
    # Test case 5
    lists5 = [createList([-2, -1]), createList([-3, 1, 4]), createList([0, 2]), createList([-1, 3])]
    print("Test 5: ", end="")
    printList(mergeKLists(lists5))
