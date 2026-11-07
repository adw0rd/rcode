def parse_positive_int(text):
    if not isinstance(text, str) or not text or any(char < '0' or char > '9' for char in text):
        return None
    return int(text)
