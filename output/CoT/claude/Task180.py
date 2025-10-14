
class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []
        self.parent = None

def reparent_tree(root, target_value):
    if root is None:
        return None
    
    target_node = find_node(root, target_value)
    if target_node is None:
        return root
    
    if target_node == root:
        return root
    
    path_to_root = []
    current = target_node
    while current is not None:
        path_to_root.append(current)
        current = current.parent
    
    for i in range(len(path_to_root) - 1):
        child = path_to_root[i]
        parent = path_to_root[i + 1]
        
        if child in parent.children:
            parent.children.remove(child)
        child.children.append(parent)
        parent.parent = child
    
    target_node.parent = None
    return target_node

def find_node(root, value):
    if root is None:
        return None
    if root.value == value:
        return root
    for child in root.children:
        found = find_node(child, value)
        if found is not None:
            return found
    return None

def build_tree(edges):
    if not edges:
        return None
    
    nodes = {}
    children_set = set()
    
    for edge in edges:
        if edge is None or len(edge) != 2:
            continue
        
        if edge[0] not in nodes:
            nodes[edge[0]] = TreeNode(edge[0])
        if edge[1] not in nodes:
            nodes[edge[1]] = TreeNode(edge[1])
        
        parent = nodes[edge[0]]
        child = nodes[edge[1]]
        
        parent.children.append(child)
        child.parent = parent
        children_set.add(edge[1])
    
    for key in nodes:
        if key not in children_set:
            return nodes[key]
    
    return list(nodes.values())[0] if nodes else None

def print_tree(root, prefix="", is_tail=True):
    if root is None:
        return
    print(prefix + ("└── " if is_tail else "├── ") + str(root.value))
    for i, child in enumerate(root.children):
        print_tree(child, 
                  prefix + ("    " if is_tail else "│   "), 
                  i == len(root.children) - 1)

if __name__ == "__main__":
    # Test case 1
    edges1 = [[0, 1], [0, 2], [0, 3], [1, 4], [1, 5], [2, 6], [2, 7], [3, 8], [3, 9]]
    root1 = build_tree(edges1)
    print("Test 1 - Original tree:")
    print_tree(root1)
    new_root1 = reparent_tree(root1, 6)
    print("\\nTest 1 - Reparented on node 6:")
    print_tree(new_root1)
    
    # Test case 2
    edges2 = [[0, 1], [0, 2]]
    root2 = build_tree(edges2)
    print("\\n\\nTest 2 - Reparent on root:")
    new_root2 = reparent_tree(root2, 0)
    print_tree(new_root2)
    
    # Test case 3
    root3 = TreeNode(0)
    print("\\n\\nTest 3 - Single node:")
    new_root3 = reparent_tree(root3, 0)
    print_tree(new_root3)
    
    # Test case 4
    edges4 = [[0, 1], [1, 2], [2, 3]]
    root4 = build_tree(edges4)
    print("\\n\\nTest 4 - Linear tree reparented on leaf:")
    new_root4 = reparent_tree(root4, 3)
    print_tree(new_root4)
    
    # Test case 5
    edges5 = [[0, 1], [0, 2]]
    root5 = build_tree(edges5)
    print("\\n\\nTest 5 - Invalid target (returns original):")
    new_root5 = reparent_tree(root5, 99)
    print_tree(new_root5)
