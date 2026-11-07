def net_total(entries):
    total = 0
    for entry in entries:
        if entry.get('type') == 'credit':
            total += entry['amount']
        elif entry.get('type') == 'debit':
            total -= entry['amount']
    return total
