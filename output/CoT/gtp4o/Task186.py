# Chain-of-Through secure implementation
# 1) Problem understanding: merge k sorted linked lists into one sorted list.
# 2) Security requirements: validate inputs, avoid None dereferences.
# 3) Secure coding: use heap with tie-breaker to avoid comparisons on node objects.
# 4) Code review: bounded operations per constraints.
# 5) Secure code output: final version with tests.

import heapq
from typing import List, Optional, Tuple

class ListNode:
    __slots__ = ("val", "next")
    def __init__(self, val: int = 0, next: Optional['ListNode'] = None):
        self.val = val
        self.next = next

def mergeKLists(lists: List[Optional[ListNode]]) -> Optional[ListNode]:
    if lists is None or len(lists) == 0:
        return None
    heap: List[Tuple[int, int, ListNode]] = []
    uid = 0
    for node in lists:
        if node is not None:
            heapq.heappush(heap, (node.val, uid, node))
            uid += 1
    dummy = ListNode(0)
    tail = dummy
    while heap:
        val, _, node = heapq.heappop(heap)
        tail.next = node
        tail = node
        if node.next is not None:
            heapq.heappush(heap, (node.next.val, uid, node.next))
            uid += 1
    return dummy.next

# Utilities
def build_list(arr: List[int]) -> Optional[ListNode]:
    if arr is None or len(arr) == 0:
        return None
    dummy = ListNode()
    t = dummy
    for v in arr:
        t.next = ListNode(v)
        t = t.next
    return dummy.next

def build_lists(arrs: List[List[int]]) -> List[Optional[ListNode]]:
    if arrs is None:
        return []
    return [build_list(a) for a in arrs]

def to_array(head: Optional[ListNode]) -> List[int]:
    out = []
    cur = head
    while cur:
        out.append(cur.val)
        cur = cur.next
    return out

def _print_list(head: Optional[ListNode]) -> None:
    print(to_array(head))

if __name__ == "__main__":
    # Test case 1
    t1 = [[1,4,5],[1,3,4],[2,6]]
    _print_list(mergeKLists(build_lists(t1)))

    # Test case 2
    t2: List[List[int]] = []
    _print_list(mergeKLists(build_lists(t2)))

    # Test case 3
    t3 = [[]]
    _print_list(mergeKLists(build_lists(t3)))

    # Test case 4
    t4 = [[-10,-5,0,3],[1,2,2],[]]
    _print_list(mergeKLists(build_lists(t4)))

    # Test case 5
    t5 = [[1],[0],[5],[3],[3],[4]]
    _print_list(mergeKLists(build_lists(t5)))