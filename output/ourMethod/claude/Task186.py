
from typing import List, Optional
import heapq

class ListNode:
    def __init__(self, val=0, next=None):
        self.val: int = val
        self.next: Optional[ListNode] = next

def mergeKLists(lists: List[Optional[ListNode]]) -> Optional[ListNode]:
    if not lists:
        return None
    
    min_heap = []
    
    for i, node in enumerate(lists):
        if node is not None:
            heapq.heappush(min_heap, (node.val, i, node))
    
    dummy = ListNode(0)
    current = dummy
    counter = len(lists)
    
    while min_heap:
        val, idx, smallest = heapq.heappop(min_heap)
        current.next = smallest
        current = current.next
        
        if smallest.next is not None:
            heapq.heappush(min_heap, (smallest.next.val, counter, smallest.next))
            counter += 1
    
    return dummy.next

def create_list(values: List[int]) -> Optional[ListNode]:
    if not values:
        return None
    dummy = ListNode(0)
    current = dummy
    for val in values:
        current.next = ListNode(val)
        current = current.next
    return dummy.next

def print_list(head: Optional[ListNode]) -> None:
    result = []
    while head is not None:
        result.append(str(head.val))
        head = head.next
    print("[" + ",".join(result) + "]")

if __name__ == "__main__":
    lists1 = [
        create_list([1, 4, 5]),
        create_list([1, 3, 4]),
        create_list([2, 6])
    ]
    print_list(mergeKLists(lists1))
    
    lists2 = []
    print_list(mergeKLists(lists2))
    
    lists3 = [None]
    print_list(mergeKLists(lists3))
    
    lists4 = [
        create_list([-2, -1, -1, 0]),
        create_list([-3])
    ]
    print_list(mergeKLists(lists4))
    
    lists5 = [
        create_list([1]),
        create_list([0])
    ]
    print_list(mergeKLists(lists5))
