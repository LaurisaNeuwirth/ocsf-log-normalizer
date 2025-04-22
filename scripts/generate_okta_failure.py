import sys
import os
import json

# Make normalize.py importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from normalize import dispatch_normalizer

# Load the raw Okta log
with open("logs_raw/okta_login_failure_raw.json") as f:
    raw_log = json.load(f)

# Use the dispatcher key that matches your DISPATCHER dictionary
normalized = dispatch_normalizer("okta_login_failure.json", raw_log)

# Write the normalized version
with open("normalized_logs/okta_login_failure_ocsf.json", "w") as f:
    json.dump(normalized, f, indent=2)

print("✅ okta_login_failure_ocsf.json created in normalized_logs/")

