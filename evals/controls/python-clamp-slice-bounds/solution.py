def slice_bounds(length, start, end):
    start, end, _ = slice(start, end).indices(length)
    return start, end
