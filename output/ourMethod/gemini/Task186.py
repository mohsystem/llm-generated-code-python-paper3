import heapq
from typing import List, Optional

class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

    # Implement __lt__ to allow direct comparison of ListNode objects in the heap
    def __lt__(self, other):
        return self.val < other.val

def mergeKLists(lists: List[Optional[ListNode]]) -> Optional[ListNode]:
    """
    Merges k sorted linked lists into one sorted linked list.
    :param lists: A list of k sorted linked lists.
    :return: The head of the merged sorted linked list.
    """
    if not lists:
        return None

    min_heap = []
    # Add the head of each non-empty list to the heap.
    for head in lists:
        if head:
            heapq.heappush(min_heap, head)
    
    # A dummy node to simplify list construction.
    dummy = ListNode(-1)
    current = dummy

    # Process nodes from the heap until it's empty.
    while min_heap:
        # Get the node with the smallest value.
        min_node = heapq.heappop(min_heap)
        
        # Append it to the result list.
        current.next = min_node
        current = current.next

        # If the extracted node has a next element, add it to the heap.
        if min_node.next:
            heapq.heappush(min_heap, min_node.next)
    
    return dummy.next

# Helper functions for testing
def create_linked_list(arr: List[int]) -> Optional[ListNode]:
    if not arr:
        return None
    dummy = ListNode(-1)
    current = dummy
    for val in arr:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

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

def main():
    # Test Case 1
    lists1 = [
        create_linked_list([1, 4, 5]),
        create_linked_list([1, 3, 4]),
        create_linked_list([2, 6])
    ]
    print("Test Case 1:")
    print_linked_list(mergeKLists(lists1))

    # Test Case 2
    lists2 = []
    print("Test Case 2:")
    print_linked_list(mergeKLists(lists2))

    # Test Case 3
    lists3 = [create_linked_list([])]
    print("Test Case 3:")
    print_linked_list(mergeKLists(lists3))

    # Test Case 4
    lists4 = [
        create_linked_list([]),
        create_linked_list([1])
    ]
    print("Test Case 4:")
    print_linked_list(mergeKLists(lists4))
    
    # Test Case 5
    lists5 = [
        create_linked_list([9]),
        create_linked_list([1, 5, 10]),
        create_linked_list([2, 3, 7, 12])
    ]
    print("Test Case 5:")
    print_linked_list(mergeKLists(lists5))

if __name__ == "__main__":
    main()