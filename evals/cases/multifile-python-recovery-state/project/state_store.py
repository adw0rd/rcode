import json

def load_state(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
