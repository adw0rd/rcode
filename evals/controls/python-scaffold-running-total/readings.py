def running_totals(values):
    total = 0
    result = []
    for value in values:
        total += value
        result.append(total)
    return result
