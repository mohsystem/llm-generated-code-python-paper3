from typing import List, Optional, Tuple
import heapq
import sys


class ListNode:
    __slots__ = ("val", "next")
    def __init__(self, val: int):
        self.val: int = val
        self.next: Optional["ListNode"] = None


def merge_k_lists(lists: List[Optional[ListNode]]) -> Optional[ListNode]:
    if lists is None:
        return None
    heap: List[Tuple[int, int, ListNode]] = []
    counter = 0
    for node in lists:
        if node is not None:
            heapq.heappush(heap, (node.val, counter, node))
            counter += 1
    dummy = ListNode(0)
    tail = dummy
    while heap:
        val, _, node = heapq.heappop(heap)
        tail.next = node
        tail = node
        if node.next is not None:
            heapq.heappush(heap, (node.next.val, counter, node.next))
            counter += 1
    return dummy.next


def build_list(arr: List[int]) -> Optional[ListNode]:
    if not isinstance(arr, list):
        raise ValueError("arr must be a list")
    if len(arr) == 0:
        return None
    dummy = ListNode(0)
    cur = dummy
    for v in arr:
        if not isinstance(v, int):
            raise ValueError("values must be integers")
        node = ListNode(v)
        cur.next = node
        cur = node
    return dummy.next


def list_to_pylist(head: Optional[ListNode]) -> List[int]:
    out: List[int] = []
    cur = head
    while cur is not None:
        out.append(cur.val)
        cur = cur.next
    return out


def main() -> None:
    # Test 1: Example 1
    t1 = [build_list([1, 4, 5]), build_list([1, 3, 4]), build_list([2, 6])]
    print(list_to_pylist(merge_k_lists(t1)))

    # Test 2: Example 2 - empty list of lists
    t2: List[Optional[ListNode]] = []
    print(list_to_pylist(merge_k_lists(t2)))

    # Test 3: Example 3 - lists = [[]]
    t3 = [build_list([])]
    print(list_to_pylist(merge_k_lists(t3)))

    # Test 4: negatives and duplicates
    t4 = [build_list([-2, -1, 3]), build_list([1, 1, 1]), build_list([2])]
    print(list_to_pylist(merge_k_lists(t4)))

    # Test 5: single list
    t5 = [build_list([0, 5, 10])]
    print(list_to_pylist(merge_k_lists(t5)))


if __name__ == "__main__":
    sys.setrecursionlimit(1000000)
    main()