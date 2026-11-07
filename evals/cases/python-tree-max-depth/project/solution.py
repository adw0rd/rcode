def max_depth(node):
    if node is None:
        return 1
    return max(max_depth(node.get('left')), max_depth(node.get('right')))
