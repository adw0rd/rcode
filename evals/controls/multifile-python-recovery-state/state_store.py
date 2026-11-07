import json

def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"count": 0}

    if isinstance(state, dict) and type(state.get("count")) is int:
        return {"count": state["count"]}
    return {"count": 0}
