import json
import sys
from state_store import load_state

print(json.dumps(load_state(sys.argv[1])))
