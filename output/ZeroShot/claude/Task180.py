
def reparent_tree(tree, new_root):
    if not tree or new_root not in tree:
        return {}
    
    result = {}
    visited = set()
    
    def build_reparented_tree(current, parent):
        visited.add(current)
        if current not in result:
            result[current] = []
        
        if current not in tree:
            return
        
        for neighbor in tree[current]:
            if neighbor not in visited:
                result[current].append(neighbor)
                build_reparented_tree(neighbor, current)
        
        if parent is not None:
            result[current].append(parent)
    
    build_reparented_tree(new_root, None)
    return result


if __name__ == "__main__":
    # Test case 1: Simple tree from example
    tree1 = {
        0: [1, 2, 3],
        1: [4, 5],
        2: [6, 7],
        3: [8, 9]
    }
    print("Test 1 - Reparent from 6:")
    print(reparent_tree(tree1, 6))
    
    # Test case 2: Single node
    tree2 = {0: []}
    print("\\nTest 2 - Single node:")
    print(reparent_tree(tree2, 0))
    
    # Test case 3: Linear tree
    tree3 = {
        0: [1],
        1: [2],
        2: [3]
    }
    print("\\nTest 3 - Linear tree, reparent from 2:")
    print(reparent_tree(tree3, 2))
    
    # Test case 4: Reparent at root (no change)
    tree4 = {
        0: [1, 2],
        1: [3]
    }
    print("\\nTest 4 - Reparent at root:")
    print(reparent_tree(tree4, 0))
    
    # Test case 5: Empty tree
    tree5 = {}
    print("\\nTest 5 - Empty tree:")
    print(reparent_tree(tree5, 0))
