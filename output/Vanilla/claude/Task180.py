
from collections import defaultdict, deque

def reparent(adjacency_list, new_root):
    new_tree = defaultdict(list)
    visited = set()
    
    def build_tree(current, parent):
        visited.add(current)
        
        for neighbor in adjacency_list.get(current, []):
            if neighbor not in visited:
                new_tree[current].append(neighbor)
                build_tree(neighbor, current)
    
    build_tree(new_root, -1)
    
    return dict(new_tree)

def main():
    # Test Case 1: Example from problem description
    tree1 = {
        0: [1, 2, 3],
        1: [0, 4, 5],
        2: [0, 6, 7],
        3: [0, 8, 9],
        4: [1],
        5: [1],
        6: [2],
        7: [2],
        8: [3],
        9: [3]
    }
    result1 = reparent(tree1, 6)
    print(f"Test 1 - Reparent on node 6: {result1}")
    
    # Test Case 2: Simple tree
    tree2 = {
        0: [1, 2],
        1: [0],
        2: [0]
    }
    result2 = reparent(tree2, 1)
    print(f"Test 2 - Reparent on node 1: {result2}")
    
    # Test Case 3: Linear tree
    tree3 = {
        0: [1],
        1: [0, 2],
        2: [1, 3],
        3: [2]
    }
    result3 = reparent(tree3, 3)
    print(f"Test 3 - Reparent on node 3: {result3}")
    
    # Test Case 4: Single node
    tree4 = {0: []}
    result4 = reparent(tree4, 0)
    print(f"Test 4 - Single node: {result4}")
    
    # Test Case 5: Three nodes
    tree5 = {
        0: [1],
        1: [0, 2],
        2: [1]
    }
    result5 = reparent(tree5, 2)
    print(f"Test 5 - Reparent on node 2: {result5}")

if __name__ == "__main__":
    main()
