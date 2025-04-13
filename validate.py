# validate.py

import json
import os
from jsonschema import validate, ValidationError

# Path to normalized logs
NORMALIZED_DIR = "normalized_logs"

# Load real OCSF schema for authentication events
with open("schemas/authentication.json") as schema_file:
    OCSF_SCHEMA = json.load(schema_file)


def validate_log_file(filepath, schema):
    with open(filepath, 'r') as f:
        data = json.load(f)

    if isinstance(data, list):
        for entry in data:
            validate_single(entry, schema, filepath)
    else:
        validate_single(data, schema, filepath)

def validate_single(log, schema, filepath):
    try:
        validate(instance=log, schema=schema)
        print(f"[PASS] {filepath}")
    except ValidationError as e:
        print(f"[FAIL] {filepath}")
        print(f"Reason: {e.message}")

def main():
    for filename in os.listdir(NORMALIZED_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(NORMALIZED_DIR, filename)
            validate_log_file

if __name__ == "__main__":
    main(