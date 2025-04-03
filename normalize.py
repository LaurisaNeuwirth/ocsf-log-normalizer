import json
from pathlib import Path
from datetime import datetime

# Input and output files
input_file = Path("logs_raw/okta_login_failure.json")
output_file = Path("logs_normalized/okta_login_failure_ocsf.json")

def normalize_okta_log(raw):
    """Normalize a raw Okta login event into OCSF format."""
    return {
        "time": raw["eventTime"],
        "class_uid": 1001,
        "class_name": "Authentication",
        "category_uid": 1,
        "category_name": "Authentication",
        "type_uid": 1,
        "type_name": "Login",
        "user": {
            "name": raw["actor"]["email"]
        },
        "status": "Failure" if raw["outcome"] == "FAILURE" else "Success",
        "src_endpoint": {
            "ip": raw["client"]["ipAddress"]
        },
        "metadata": {
            "vendor_name": "Okta",
            "product_name": "Okta Identity Cloud",
            "original_event": raw
        }
    }

def main():
    if not input_file.exists():
        print(f"[ERROR] File not found: {input_file}")
        return

    with input_file.open() as f:
        raw_event = json.load(f)

    normalized_event = normalize_okta_log(raw_event)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w") as f:
        json.dump(normalized_event, f, indent=2)

    print(f"[✅] Normalized event written to: {output_file}")

if __name__ == "__main__":
    main()
