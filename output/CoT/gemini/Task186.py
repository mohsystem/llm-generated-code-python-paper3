import heapq
from typing import List, Optional

# Definition for singly-linked list.
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

class Solution:
    def mergeKLists(self, lists: List[Optional[ListNode]]) -> Optional[ListNode]:
        if not lists:
            return None

        min_heap = []
        # In Python, if two items have the same priority, the heap might try to compare
        # the next item in the tuple (the ListNode object), which is not comparable.
        # Adding a unique counter `i` as a tie-breaker avoids this issue.
        counter = 0 
        for head in lists:
            if head:
                heapq.heappush(min_heap, (head.val, counter, head))
                counter += 1

        dummy = ListNode(0)
        tail = dummy

        while min_heap:
            val, _, node = heapq.heappop(min_heap)
            tail.next = node
            tail = tail.next

            if node.next:
                heapq.heappush(min_heap, (node.next.val, counter, node.next))
                counter += 1
        
        return dummy.next

# Helper function to create a linked list from a list of integers
def create_list(arr):
    if not arr:
        return None
    dummy = ListNode(0)
    current = dummy
    for val in arr:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

# Helper function to print a linked list
def print_list(head):
    if not head:
        print("[]")
        return
    
    nodes = []
    current = head
    while current:
        nodes.append(str(current.val))
        current = current.next
    print("[" + ", ".join(nodes) + "]")

if __name__ == "__main__":
    solution = Solution()

    # Test Case 1
    print("Test Case 1:")
    lists1 = [
        create_list([1, 4, 5]),
        create_list([1, 3, 4]),
        create_list([2, 6])
    ]
    print("Input:")
    for l in lists1: print_list(l)
    result1 = solution.mergeKLists(lists1)
    print("Output:", end=" ")
    print_list(result1)
    print()

    # Test Case 2
    print("Test Case 2:")
    lists2 = []
    print("Input: []")
    result2 = solution.mergeKLists(lists2)
    print("Output:", end=" ")
    print_list(result2)
    print()
    
    # Test Case 3
    print("Test Case 3:")
    lists3 = [create_list([])]
    print("Input: [[]]")
    result3 = solution.mergeKLists(lists3)
    print("Output:", end=" ")
    print_list(result3)
    print()

    # Test Case 4
    print("Test Case 4:")
    lists4 = [
        create_list([]),
        create_list([1])
    ]
    print("Input:")
    for l in lists4: print_list(l)
    result4 = solution.mergeKLists(lists4)
    print("Output:", end=" ")
    print_list(result4)
    print()
    
    # Test Case 5
    print("Test Case 5:")
    lists5 = [
        create_list([10, 20]),
        create_list([5, 15]),
        create_list([1, 2, 22])
    ]
    print("Input:")
    for l in lists5: print_list(l)
    result5 = solution.mergeKLists(lists5)
    print("Output:", end=" ")
    print_list(result5)
    print()