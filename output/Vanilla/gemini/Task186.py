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

        pq = []
        # Use a counter to break ties for nodes with the same value,
        # as heapq cannot compare ListNode objects directly.
        counter = 0
        for head in lists:
            if head:
                heapq.heappush(pq, (head.val, counter, head))
                counter += 1

        dummy = ListNode(-1)
        tail = dummy

        while pq:
            _, _, node = heapq.heappop(pq)
            tail.next = node
            tail = tail.next
            if node.next:
                heapq.heappush(pq, (node.next.val, counter, node.next))
                counter += 1
        
        return dummy.next

# Helper function to create a linked list from a list
def create_linked_list(arr: List[int]) -> Optional[ListNode]:
    if not arr:
        return None
    dummy = ListNode(-1)
    current = dummy
    for val in arr:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

# Helper function to print a linked list
def print_linked_list(head: Optional[ListNode]):
    if not head:
        print("[]")
        return
    
    result = []
    current = head
    while current:
        result.append(current.val)
        current = current.next
    print(result)

# Python does not require manual memory management for list nodes
def delete_linked_list(head: Optional[ListNode]):
    pass

if __name__ == '__main__':
    solution = Solution()

    # Test Case 1: Example 1
    print("Test Case 1:")
    lists1 = [
        create_linked_list([1, 4, 5]),
        create_linked_list([1, 3, 4]),
        create_linked_list([2, 6])
    ]
    result1 = solution.mergeKLists(lists1)
    print_linked_list(result1)
    delete_linked_list(result1)

    # Test Case 2: Example 2
    print("\nTest Case 2:")
    lists2 = []
    result2 = solution.mergeKLists(lists2)
    print_linked_list(result2)
    delete_linked_list(result2)

    # Test Case 3: Example 3
    print("\nTest Case 3:")
    lists3 = [create_linked_list([])]
    result3 = solution.mergeKLists(lists3)
    print_linked_list(result3)
    delete_linked_list(result3)

    # Test Case 4: lists with null and single elements
    print("\nTest Case 4:")
    lists4 = [
        create_linked_list([1]),
        None,
        create_linked_list([0])
    ]
    result4 = solution.mergeKLists(lists4)
    print_linked_list(result4)
    delete_linked_list(result4)

    # Test Case 5: lists with negative numbers
    print("\nTest Case 5:")
    lists5 = [
        create_linked_list([-2, -1, 0]),
        create_linked_list([-3, 1, 2]),
        create_linked_list([-5, 5, 10])
    ]
    result5 = solution.mergeKLists(lists5)
    print_linked_list(result5)
    delete_linked_list(result5)