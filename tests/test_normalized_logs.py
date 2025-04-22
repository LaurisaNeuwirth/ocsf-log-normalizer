import os
import json
import pytest
from jsonschema import validate, ValidationError

# Mapping each normalized log to its schema
SCHEMA_MAPPING = {
    "okta_login_failure_ocsf.json": "Authentication.json",
    "okta_failure_ocsf.json": "Authentication.json",
    "aws_cloudtrail_console_login_success_ocsf.json": "Authentication.json",
    "bitdefender_syslog_threatdetected_ocsf.json": "Malware.json",
    "nginx_access_login_success_ocsf.json": "WebActivity.json",
    "zeek_http_request_success_ocsf.json": "network_activity_schema.json"
}

# Required fields for each schema
REQUIRED_FIELDS = {
    "Authentication.json": ["event_name", "timestamp", "severity"],
    "Malware.json": ["event_name", "timestamp", "malware_name"],
    "WebActivity.json": ["event_name", "src_ip", "user_agent"],
    "network_activity_schema.json": ["event_name", "protocol", "src_ip", "dst_ip"],
}

NORMALIZED_DIR = "normalized_logs"
SCHEMA_DIR = "schemas"

@pytest.mark.parametrize("filename", SCHEMA_MAPPING.keys())
def test_normalized_log_against_schema(filename):
    schema_path = os.path.join(SCHEMA_DIR, SCHEMA_MAPPING[filename])
    data_path = os.path.join(NORMALIZED_DIR, filename)

    with open(schema_path) as sf:
        schema = json.load(sf)

    with open(data_path) as df:
        data = json.load(df)

    try:
        validate(instance=data, schema=schema)

        # Check for required fields
        required_fields = REQUIRED_FIELDS.get(SCHEMA_MAPPING[filename], [])
        missing_fields = [field for field in required_fields if field not in data]
        assert not missing_fields, f"Missing required fields in {filename}: {missing_fields}"

    except ValidationError as e:
        error_path = " -> ".join([str(p) for p in e.path]) or "(root)"
        pytest.fail(f"\n❌ Validation failed for {filename}\n"
                    f"📍 Path: {error_path}\n"
                    f"🧾 Message: {e.message}\n"
                    f"🔎 Invalid value: {e.instance}")
