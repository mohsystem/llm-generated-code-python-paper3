
import heapq

class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next

class Task186:
    @staticmethod
    def mergeKLists(lists):
        if not lists:
            return None
        
        heap = []
        counter = 0
        
        for i, node in enumerate(lists):
            if node:
                heapq.heappush(heap, (node.val, counter, node))
                counter += 1
        
        dummy = ListNode(0)
        current = dummy
        
        while heap:
            val, _, node = heapq.heappop(heap)
            current.next = node
            current = current.next
            
            if node.next:
                heapq.heappush(heap, (node.next.val, counter, node.next))
                counter += 1
        
        return dummy.next
    
    @staticmethod
    def create_list(arr):
        if not arr:
            return None
        dummy = ListNode(0)
        current = dummy
        for val in arr:
            current.next = ListNode(val)
            current = current.next
        return dummy.next
    
    @staticmethod
    def print_list(head):
        result = []
        while head:
            result.append(str(head.val))
            head = head.next
        print("[" + ",".join(result) + "]")

if __name__ == "__main__":
    solution = Task186()
    
    # Test case 1
    lists1 = [solution.create_list([1,4,5]), solution.create_list([1,3,4]), solution.create_list([2,6])]
    print("Test 1: ", end="")
    solution.print_list(solution.mergeKLists(lists1))
    
    # Test case 2
    lists2 = []
    print("Test 2: ", end="")
    solution.print_list(solution.mergeKLists(lists2))
    
    # Test case 3
    lists3 = [None]
    print("Test 3: ", end="")
    solution.print_list(solution.mergeKLists(lists3))
    
    # Test case 4
    lists4 = [solution.create_list([1,2,3]), solution.create_list([4,5,6])]
    print("Test 4: ", end="")
    solution.print_list(solution.mergeKLists(lists4))
    
    # Test case 5
    lists5 = [solution.create_list([-2,-1,0]), solution.create_list([-3]), solution.create_list([1,2])]
    print("Test 5: ", end="")
    solution.print_list(solution.mergeKLists(lists5))
