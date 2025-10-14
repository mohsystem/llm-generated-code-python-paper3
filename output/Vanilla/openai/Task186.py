import heapq

class ListNode:
    def __init__(self, val=0, nxt=None):
        self.val = val
        self.next = nxt

def mergeKLists(lists):
    heap = []
    counter = 0  # To avoid comparison issues when values are equal
    for node in lists:
        if node:
            heapq.heappush(heap, (node.val, counter, node))
            counter += 1
    dummy = ListNode(0)
    tail = dummy
    while heap:
        _, _, n = heapq.heappop(heap)
        tail.next = n
        tail = n
        if n.next:
            heapq.heappush(heap, (n.next.val, counter, n.next))
            counter += 1
    tail.next = None
    return dummy.next

# Helpers
def build_list(arr):
    dummy = ListNode(0)
    t = dummy
    for v in arr:
        t.next = ListNode(v)
        t = t.next
    return dummy.next

def build_lists(list_of_lists):
    return [build_list(arr) for arr in list_of_lists]

def to_array(head):
    res = []
    while head:
        res.append(head.val)
        head = head.next
    return res

if __name__ == "__main__":
    tests = [
        [[1,4,5],[1,3,4],[2,6]],
        [],
        [[]],
        [[-10,-5,0,5],[1,2,3],[-10,-10,100]],
        [[1],[0],[-1,2,2],[],[3,3,3]]
    ]
    for case in tests:
        lists = build_lists(case)
        merged = mergeKLists(lists)
        print(to_array(merged))