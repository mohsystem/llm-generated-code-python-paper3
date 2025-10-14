import collections

class Node:
    def __init__(self, value):
        self.value = value
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)
        return self

def _build_adjacency_list(node, adj, nodes):
    if not node:
        return
    nodes.add(node.value)
    if node.value not in adj:
        adj[node.value] = []
    for child in node.children:
        if child.value not in adj:
            adj[child.value] = []
        adj[node.value].append(child.value)
        adj[child.value].append(node.value)
        _build_adjacency_list(child, adj, nodes)

def _build_new_tree_from_adjacency_list(root_value, adj):
    new_root = Node(root_value)
    queue = collections.deque([new_root])
    visited = {root_value}

    while queue:
        current_node = queue.popleft()
        if current_node.value in adj:
            # Sort neighbors for deterministic output for tests
            neighbors = sorted(adj[current_node.value])
            for neighbor_value in neighbors:
                if neighbor_value not in visited:
                    visited.add(neighbor_value)
                    child_node = Node(neighbor_value)
                    current_node.children.append(child_node)
                    queue.append(child_node)
    return new_root

def reparent_tree(old_root, new_root_value):
    if not old_root:
        return None
    
    adj = {}
    nodes = set()
    _build_adjacency_list(old_root, adj, nodes)

    if new_root_value not in nodes:
        return None

    return _build_new_tree_from_adjacency_list(new_root_value, adj)

def print_tree(node, prefix="", is_tail=True):
    if not node:
        return
    print(prefix + ("└── " if is_tail else "├── ") + str(node.value))
    for i, child in enumerate(node.children):
        is_last_child = (i == len(node.children) - 1)
        print_tree(child, prefix + ("    " if is_tail else "│   "), is_last_child)

if __name__ == '__main__':
    # Test Case 1: Example from prompt
    print("--- Test Case 1: Re-parenting on node 6 ---")
    root1 = Node(0)
    n1 = Node(1)
    n2 = Node(2)
    n3 = Node(3)
    n1.add_child(Node(4)).add_child(Node(5))
    n2.add_child(Node(6)).add_child(Node(7))
    n3.add_child(Node(8)).add_child(Node(9))
    root1.add_child(n1).add_child(n2).add_child(n3)
    
    print("Original tree (rooted at 0):")
    print_tree(root1)
    
    new_root1 = reparent_tree(root1, 6)
    print("\nNew tree (re-rooted at 6):")
    print_tree(new_root1)
    print("\n" + "=" * 40)
    
    # Test Case 2: Re-rooting at the current root (0)
    print("--- Test Case 2: Re-parenting on current root 0 ---")
    print("Original tree (rooted at 0):")
    print_tree(root1)
    
    new_root2 = reparent_tree(root1, 0)
    print("\nNew tree (re-rooted at 0):")
    print_tree(new_root2)
    print("\n" + "=" * 40)
    
    # Test Case 3: Re-rooting at a leaf node (9)
    print("--- Test Case 3: Re-parenting on leaf node 9 ---")
    print("Original tree (rooted at 0):")
    print_tree(root1)
    
    new_root3 = reparent_tree(root1, 9)
    print("\nNew tree (re-rooted at 9):")
    print_tree(new_root3)
    print("\n" + "=" * 40)
    
    # Test Case 4: Linear tree
    print("--- Test Case 4: Linear tree ---")
    root4 = Node(0)
    root4.add_child(Node(1).add_child(Node(2).add_child(Node(3))))
    print("Original tree (rooted at 0):")
    print_tree(root4)

    new_root4 = reparent_tree(root4, 2)
    print("\nNew tree (re-rooted at 2):")
    print_tree(new_root4)
    print("\n" + "=" * 40)
    
    # Test Case 5: Tree with a single node
    print("--- Test Case 5: Single node tree ---")
    root5 = Node(42)
    print("Original tree (rooted at 42):")
    print_tree(root5)

    new_root5 = reparent_tree(root5, 42)
    print("\nNew tree (re-rooted at 42):")
    print_tree(new_root5)
    print("\n" + "=" * 40)