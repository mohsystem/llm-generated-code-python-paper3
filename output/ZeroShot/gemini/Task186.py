import heapq
from typing import List, Optional

# Definition for singly-linked list.
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

    # Implement __lt__ (less than) for heapq to compare nodes directly.
    # This is necessary if two nodes have the same value, as Python 3's
    # heapq will otherwise try to compare the node objects themselves.
    def __lt__(self, other):
        return self.val < other.val

class Solution:
    """
    Merges k sorted linked lists into one single sorted linked list.
    This implementation uses a min-heap to efficiently find the minimum
    node among the heads of all lists.
    """
    def mergeKLists(self, lists: List[Optional[ListNode]]) -> Optional[ListNode]:
        # Handle edge case of empty or null input list
        if not lists:
            return None

        # A min-heap to store the head nodes of the k lists.
        min_heap = []
        
        # Add the head of each non-empty list to the priority queue.
        for head in lists:
            if head:
                heapq.heappush(min_heap, head)
        
        # A dummy node to simplify the construction of the result list.
        dummy = ListNode(-1)
        tail = dummy
        
        # Process nodes from the heap until it's empty.
        while min_heap:
            # Get the node with the smallest value.
            min_node = heapq.heappop(min_heap)
            
            # Append it to the result list.
            tail.next = min_node
            tail = tail.next
            
            # If the extracted node has a next element, add it to the heap.
            if min_node.next:
                heapq.heappush(min_heap, min_node.next)
        
        return dummy.next

# --- Main execution block for testing ---
def create_list(arr: List[int]) -> Optional[ListNode]:
    """Helper function to create a linked list from a list of integers."""
    if not arr:
        return None
    dummy = ListNode(-1)
    current = dummy
    for val in arr:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

def print_list(head: Optional[ListNode]):
    """Helper function to print a linked list."""
    current = head
    while current:
        print(current.val, end=" -> ")
        current = current.next
    print("NULL")

if __name__ == '__main__':
    solution = Solution()
    print("--- Python Tests ---")

    # Test Case 1: Example 1
    lists1 = [
        create_list([1, 4, 5]),
        create_list([1, 3, 4]),
        create_list([2, 6])
    ]
    print("Test Case 1: ", end="")
    print_list(solution.mergeKLists(lists1))

    # Test Case 2: Example 2 (empty list of lists)
    lists2 = []
    print("Test Case 2: ", end="")
    print_list(solution.mergeKLists(lists2))

    # Test Case 3: Example 3 (list with one empty list)
    lists3 = [create_list([])]
    print("Test Case 3: ", end="")
    print_list(solution.mergeKLists(lists3))

    # Test Case 4: Mix of empty and non-empty lists
    lists4 = [
        create_list([1, 2, 3]),
        create_list([]),
        create_list([4, 5])
    ]
    print("Test Case 4: ", end="")
    print_list(solution.mergeKLists(lists4))

    # Test Case 5: Edge case with small lists
    lists5 = [
        create_list([1]),
        create_list([0])
    ]
    print("Test Case 5: ", end="")
    print_list(solution.mergeKLists(lists5))