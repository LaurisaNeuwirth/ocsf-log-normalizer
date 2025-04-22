import json
from pathlib import Path
from datetime import datetime, timezone


import os

RAW_DIR = "logs_raw"
NORMALIZED_DIR = "normalized_logs"

# Input and output files
input_file = Path("logs_raw/okta_login_failure.json")
output_file = Path("logs_normalized/okta_login_failure_ocsf.json")

def normalize_okta_log(raw_log):
    user_email = (
        raw_log.get("actor", {}).get("email") or
        raw_log.get("actor", {}).get("alternateId")
    )

    event_time = raw_log.get("eventTime") or raw_log.get("published")

    return {
        "class_uid": 1001,
        "class_name": "Authentication",
        "category_uid": 1,
        "category_name": "Authentication",
        "type_uid": 1,
        "type_name": "Login",
        "event_name": "User login failed",
        "severity": 3,
        "time": event_time,
        "timestamp": event_time,
        "status": "Failure" if raw_log.get("outcome") == "FAILURE" or raw_log.get("outcome", {}).get("result") == "FAILURE" else "Success",
        "user": {
            "uid": user_email,
            "name": user_email,
            "email_addr": user_email
        },
        "src_endpoint": {
            "ip": raw_log.get("client", {}).get("ipAddress"),
            "user_agent": {
                "original": raw_log.get("client", {}).get("userAgent", {}).get("rawUserAgent")
            }
        },
        "metadata": {
            "vendor_name": "Okta",
            "product_name": "Okta Identity Cloud",
            "app": raw_log.get("app"),
            "uuid": raw_log.get("uuid"),
            "original_event": raw_log
        }
    }

def normalize_bitdefender_threat_detected(raw_log):
    return {
        "class_uid": 3004,
        "category_uid": 3,
        "metadata": {
            "product": "Bitdefender",
            "vendor_name": "Bitdefender",
            "version": "syslog"
        },
        "time": raw_log.get("timestamp"),
        "severity": raw_log.get("severity").capitalize(),
        "status": "Success",
        "user": {
            "uid": raw_log.get("user"),
            "name": raw_log.get("user")
        },
        "src_endpoint": {
            "ip": raw_log.get("host_ip"),
            "hostname": raw_log.get("host_name")
        },
        "malware": {
            "name": raw_log.get("threat_name"),
            "path": raw_log.get("file_path")
        },
        "disposition": raw_log.get("action_taken")
    }

def normalize_cloudtrail_login_success(raw_log):
    return {
        "class_uid": 1001,
        "category_uid": 1,
        "metadata": {
            "product": "AWS CloudTrail",
            "vendor_name": "Amazon",
            "version": raw_log.get("eventVersion")
        },
        "time": raw_log.get("eventTime"),
        "status": raw_log.get("responseElements", {}).get("ConsoleLogin"),
        "user": {
            "uid": raw_log.get("userIdentity", {}).get("arn"),
            "name": raw_log.get("userIdentity", {}).get("userName")
        },
        "auth_protocol": raw_log.get("eventName"),
        "src_endpoint": {
            "ip": raw_log.get("sourceIPAddress")
        },
        "user_agent": raw_log.get("userAgent"),
        "mfa_used": raw_log.get("additionalEventData", {}).get("MFAUsed") == "Yes"
    }

def normalize_nginx(log):
    request_parts = log.get("request", "").split()
    http_method = request_parts[0] if len(request_parts) >= 1 else None
    url = request_parts[1] if len(request_parts) >= 2 else None

    return {
        "category": "web",
        "class_uid": 8000,
        "class_name": "Web activity",
        "event_type": "access",
        "event_uid": 800000,
        "event_time": log.get("time"),
        "severity_id": 1,
        "status_code": log.get("status"),
        "response_size": log.get("body_bytes_sent"),
        "src_endpoint": {
            "ip": log.get("remote_addr")
        },
        "http_request": {
            "method": http_method,
            "url": url,
            "referrer": log.get("http_referer"),
            "user_agent": log.get("http_user_agent")
        },
        "metadata": {
            "source": "nginx"
        }
    }

print("Running normalize.py...")
print("Files in raw logs directory:", os.listdir(RAW_DIR))

def normalize_zeek_conn(raw_log):
    return {
        "class_uid": 2001,
        "class_name": "Network Activity",
        "category_uid": 2,
        "category_name": "Network",
        "activity_name": "Connection",
        "time": datetime.fromtimestamp(float(raw_log.get("ts")), tz=timezone.utc).isoformat(),
        "src_endpoint": {
            "ip": raw_log.get("id.orig_h"),
            "port": raw_log.get("id.orig_p")
        },
        "dst_endpoint": {
            "ip": raw_log.get("id.resp_h"),
            "port": raw_log.get("id.resp_p")
        },
        "protocol_name": str(raw_log.get("proto") or "unknown"),
        "direction": str(raw_log.get("conn_state") or "unknown"),
        "metadata": {
            "vendor_name": "Zeek",
            "product_name": "Zeek Network Monitor",
            "original_event": raw_log
        }
    }

DISPATCHER = {
    "AWS_cloudtrail_console_login_success.json": normalize_cloudtrail_login_success,
    "okta_login_failure.json": normalize_okta_log,
    "okta_failure_raw.json": normalize_okta_log,
    "bitdefender_syslog_threatdetected.json": normalize_bitdefender_threat_detected,
    "nginx_access_login_success.json": normalize_nginx,
    "zeek_http_request_success.json": normalize_zeek_conn,
}


def main():
    print("Running normalize.py...")
    print("Files in raw logs directory:", os.listdir(RAW_DIR))

    for filename in os.listdir(RAW_DIR):
        filepath = os.path.join(RAW_DIR, filename)
        print(f"Checking file: {filename}")
        print(f"DEBUG: filename == {repr(filename)}")

        normalizer = DISPATCHER.get(filename)
        if not normalizer:
            print(f"No match found for: {filename}")
            continue

        print(f"Normalizing {filename}...")
        with open(filepath) as f:
            raw_data = json.load(f)

        normalized = normalizer(raw_data)
        output_file = os.path.join(NORMALIZED_DIR, filename.replace(".json", "_ocsf.json"))

        # Save the normalized log
        with open(output_file, "w") as out:
            json.dump(normalized, out, indent=2)
        print(f"Saved normalized log to {output_file}") 


if __name__ == "__main__":
    main()

def dispatch_normalizer(filename, raw_log):
    normalizer = DISPATCHER.get(filename)
    if not normalizer:
        raise ValueError(f"No normalizer found for: {filename}")
    return normalizer(raw_log)
