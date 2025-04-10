# ocsf-log-normalizer

NOTE: I am in the midst of creating this and exoect to be done by April 13.
Normalize security logs to the OCSF format, validate schema consistency, and detect schema drift over time.

This project ingests raw security logs (e.g., Okta, CrowdStrike, AWS CloudTrail), normalizes them into the [Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io/) format, and validates them using JSON Schemas.

## Features

- Normalizes raw JSON logs into OCSF-compliant events
- Validates log structure and field types using versioned JSON schemas
- Detects schema drift (e.g., field changes, type mismatches, unexpected values)
- Optional: Generates dashboards or metrics from normalized logs
- Built with GitHub Codespaces and Python

---

## Project Structure

ocsf-log-normalizer/ ├── logs_raw/ # Raw input logs (sampled or real) ├── logs_normalized/ # Normalized logs in OCSF format ├── schemas/ # JSON Schema files for OCSF validation ├── tests/ # Schema validation and drift detection scripts ├── dashboard/ # Optional dashboard scripts (e.g. pandas or Streamlit) ├── normalize.py # Raw log → OCSF normalizer ├── validate.py # Validates logs against schema ├── drift_check.py # Detects schema changes over time └── .github/workflows/ # GitHub Actions CI setup

##  Goals

This project aims to help security teams:
- Create a consistent format for logs across vendors
- Catch silent log schema changes from upstream sources
- Build OCSF-compliant pipelines that are testable and reliable

---

##  ToDo

- Sample logs from Okta, AWS, Defender
- GitHub Actions for automatic schema validation
- Visual dashboards from normalized logs

