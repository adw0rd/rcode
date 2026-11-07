def safe_label(text):
    normalized = text.lower().replace(' ', '-')
    return ''.join(char for char in normalized if ('a' <= char <= 'z') or ('0' <= char <= '9') or char == '-')
