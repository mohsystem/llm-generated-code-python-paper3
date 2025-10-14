import collections

def _build_tree_recursive(current_node_id, parent_id, adj):
    node = {'id': current_node_id, 'children': []}
    
    # Sort neighbors for deterministic output
    sorted_neighbors = sorted(adj.get(current_node_id, []))

    for neighbor_id in sorted_neighbors:
        if neighbor_id != parent_id:
            node['children'].append(_build_tree_recursive(neighbor_id, current_node_id, adj))
    return node

def reparent_tree(edges, new_root):
    """
    Reparents a tree on a selected node.

    Args:
        edges: A list of tuples, where each tuple represents an edge.
        new_root: The id of the node to become the new root.

    Returns:
        A dictionary representing the new rooted tree, or None if new_root is not in the tree.
    """
    if not isinstance(edges, list):
        return None
        
    if not edges:
        return {'id': new_root, 'children': []}

    adj = collections.defaultdict(list)
    nodes = set()
    for u, v in edges:
        adj[u].append(v)
        adj[v].append(u)
        nodes.add(u)
        nodes.add(v)
    
    if new_root not in nodes:
        return None

    return _build_tree_recursive(new_root, -1, adj) # Using -1 as a virtual parent

def print_tree(node, prefix=""):
    if node is None:
        print("Tree is None.")
        return
    print(prefix + str(node['id']))
    # Sort children before printing for consistent output
    sorted_children = sorted(node.get('children', []), key=lambda x: x['id'])
    for child in sorted_children:
        print_tree(child, prefix + "  ")

def main():
    edges_list = [
        # Test Case 1: From prompt
        [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 6), (2, 7), (3, 8), (3, 9)],
        # Test Case 2: Reparent on original root
        [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 6), (2, 7), (3, 8), (3, 9)],
        # Test Case 3: Reparent on a leaf
        [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 6), (2, 7), (3, 8), (3, 9)],
        # Test Case 4: Smaller tree
        [(1, 0), (2, 0), (3, 1), (4, 1)],
        # Test Case 5: Line graph
        [(0, 1), (1, 2), (2, 3)]
    ]
    new_roots = [6, 0, 9, 1, 2]

    for i in range(len(edges_list)):
        print(f"--- Test Case {i + 1} ---")
        print(f"Reparenting on node {new_roots[i]}")
        new_tree = reparent_tree(edges_list[i], new_roots[i])
        print_tree(new_tree)
        print()

if __name__ == "__main__":
    main()