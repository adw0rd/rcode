def max_depth(node):
    if node is None:
        return 0
    return 1 + max(max_depth(node.get('left')), max_depth(node.get('right')))
