import json
import sys
from names import normalize_names

print(json.dumps(normalize_names(json.load(sys.stdin))))
