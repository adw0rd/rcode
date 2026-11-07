def slice_bounds(length, start, end):
    # Вернуть ограниченные границы полуоткрытого среза.
    return max(0, start), min(length, end)
