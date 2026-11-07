def multiply_config(config):
    return {"result": config.get("base", 0) * (config.get("multiplier") or 1)}
