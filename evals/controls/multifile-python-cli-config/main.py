import json
import sys
from config_math import multiply_config

config = json.load(sys.stdin)
print(json.dumps(multiply_config(config)))
