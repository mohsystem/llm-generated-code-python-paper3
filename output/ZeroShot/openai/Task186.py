import heapq
from typing import List, Optional

class ListNode:
    def __init__(self, val: int = 0, next: Optional['ListNode'] = None):
        self.val = val
        self.next = next

def mergeKLists(lists: List[Optional[ListNode]]) -> Optional[ListNode]:
    if lists is None or len(lists) == 0:
        return None
    heap = []
    for idx, node in enumerate(lists):
        if node is not None:
            heapq.heappush(heap, (node.val, id(node), node))
    dummy = ListNode(0)
    tail = dummy
    while heap:
        _, _, node = heapq.heappop(heap)
        tail.next = node
        tail = node
        if node.next is not None:
            heapq.heappush(heap, (node.next.val, id(node.next), node.next))
    tail.next = None
    return dummy.next

# Helpers
def build_list(arr: List[int]) -> Optional[ListNode]:
    dummy = ListNode(0)
    cur = dummy
    for v in arr:
        cur.next = ListNode(v)
        cur = cur.next
    return dummy.next

def to_list(head: Optional[ListNode]) -> List[int]:
    out = []
    while head:
        out.append(head.val)
        head = head.next
    return out

def main():
    # Test 1
    t1 = [build_list([1,4,5]), build_list([1,3,4]), build_list([2,6])]
    print(to_list(mergeKLists(t1)))

    # Test 2
    t2: List[Optional[ListNode]] = []
    print(to_list(mergeKLists(t2)))

    # Test 3
    t3 = [build_list([])]
    print(to_list(mergeKLists(t3)))

    # Test 4
    t4 = [build_list([-10,-5,0,5]), build_list([-6,-3,2,2,7]), build_list([])]
    print(to_list(mergeKLists(t4)))

    # Test 5
    t5 = [build_list([1]), build_list([]), build_list([]), build_list([0]), build_list([1,1,1]), build_list([-1,2])]
    print(to_list(mergeKLists(t5)))

if __name__ == "__main__":
    main()