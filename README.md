# ocsf-log-normalizer

> Normalize security logs to the OCSF format, validate schema consistency, and detect schema drift over time.

This project ingests raw security logs from  AWS CloudTrail, Bitdefender, Nginx, Okta and Zeek, normalizes them into the Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io/) format, and validates them using JSON Schemas.

## Goals

This project aims to help security teams:

- Create a consistent format for logs across 5 commonly use cybersecurity vendors
- Catch silent log schema changes from upstream sources
- Build OCSF-compliant pipelines that are testable and reliable

## Features

- Normalizes raw JSON logs into OCSF-compliant events
- Validates log structure and field types using versioned JSON schemas
- Detects schema drift (e.g., field changes, type mismatches, unexpected values)
- Optional: Generates dashboards or metrics from normalized logs
- Built with GitHub Codespaces and Python

## Project Structure
ocsf-log-normalizer/
├── logs_raw/               # Raw input logs (sampled)
├── normalized_logs/        # Logs normalized into OCSF format
├── schemas/                # JSON Schema files for OCSF validation
├── tests/                  # Unit tests for schema compliance and drift detection
├── dashboard/              # To Do: dashboards using pandas or Streamlit
├── normalize.py            # Main normalization script (raw → OCSF)
├── validate.py             # Validates logs against the appropriate schema
├── drift_check.py          # Detects schema drift over time
└── .github/workflows/      # GitHub Actions CI for test automation


## OCSF Category UID Reference

| `category_uid` | Category Name       | Description                             |
|----------------|---------------------|-----------------------------------------|
| `1`            | Authentication      | Login events, session starts/failures   |
| `2`            | Network Activity    | Web traffic, firewall, proxy logs       |
| `3`            | Threat Detection    | Malware detections, EDR alerts          |
| `4`            | DLP                 | Data exfiltration, file block logs      |
| `5`            | Resource Access     | File access, database reads/writes      |
| `6`            | Configuration       | Policy or setting changes               |
| `7`            | Audit               | Admin or privileged user activity       |

---

## Example Normalized Logs

The following example files show how raw logs from different sources are transformed into [OCSF](https://schema.ocsf.io/) format:

- [`nginx_access_login_success_ocsf.json`](normalized_logs/nginx_access_login_success_ocsf.json)
- [`okta_login_failure_ocsf.json`](normalized_logs/okta_login_failure_ocsf.json)
- [`aws_cloudtrail_console_login_success_ocsf.json`](normalized_logs/aws_cloudtrail_console_login_success_ocsf.json)
- [`bitdefender_syslog_threatdetected_ocsf.json`](normalized_logs/bitdefender_syslog_threatdetected_ocsf.json)
- [`zeek_http_request_success_ocsf.json`](normalized_logs/zeek_http_request_success_ocsf.json)

---

## Dispatcher Pattern for Log Normalization

This project uses a dispatcher pattern in `normalize.py` to route logs to the correct normalization function based on filename.

A dispatcher is a dictionary that maps inputs (like filenames) to functions. It replaces long `if/elif` chains with a clean, scalable structure.

**Instead of this:**
```python
if filename == "okta.json":
    normalize_okta()
elif filename == "zeek.json":
    normalize_zeek()

We use this:
DISPATCH = {
    "okta.json": normalize_okta,
    "zeek.json": normalize_zeek,
}
DISPATCH[filename](raw_log)
```

Why It’s Better
- Easier to extend: just add one function + one dictionary key
- Cleaner and more readable than nested if/elif
- Test-friendly: each log type is modular and isolated
- Scales well across many log types

## Log Ingestion
This project uses simulated log ingestion by loading public sample logs from common security tools and services. These samples represent real-world formats but are stored locally in logs_raw/ for easy testing and development.


## Currently Supported Log Types

| Source         | Format            | Log Types                             |
|----------------|-------------------|----------------------------------------|
| Okta           | JSON              | Login failures, session events         |
| AWS CloudTrail | JSON              | Console login activity                 |
| Zeek           | JSON (converted)  | HTTP requests, connection logs         |
| Bitdefender    | Simulated JSON    | Threat detection events                |
| NGINX          | Access log (text) | Web traffic (e.g., successful logins)  |
``



Logs are sourced from vendor documentation, test datasets, or simulated where real data isn't available.

In future versions, this project may include live ingestion from APIs or S3.

## Testing & Schema Validation

This project uses pytest for automated validation and jsonschema for enforcing OCSF compliance.

What It Does:
Loads each normalized log in normalized_logs/
Maps it to the correct schema in schemas/ via filename
Validates required fields, data types, and formats
Fails early if schema drift or invalid data is detected

Run the tests:
pytest tests/

 ## ToDo

 Update README to explain the schma drift detection
 Upgraded logs from Okta, AWS, Defender, Zeek
 GitHub Actions for automatic schema validation
 Visual dashboards from normalized logs with links to normalized logs on each run
 Update to ingest looping to simulate live ingestion