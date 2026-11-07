def parse_positive_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None
