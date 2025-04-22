#!/bin/bash

# Exit on error
set -e

echo "✅ Creating GitHub issues..."

# --- ISSUES ---
gh issue create --title "Create sample_logs/ directory for storing raw vendor logs" \
  --body "Set up a dedicated folder (sample_logs/) to store real-world log examples from AWS, Okta, Zeek, etc. This will help keep raw logs organized and separate from normalized_logs/."

gh issue create --title "Add AWS CloudTrail ConsoleLogin sample log" \
  --body "Pull a sample login event from AWS documentation and save it to sample_logs/aws_console_login.json. This will be normalized into the Authentication schema."

gh issue create --title "Add Okta login failure event sample log" \
  --body "Download a system log event from Okta's developer docs showing a failed login. Save it as sample_logs/okta_login_failure.json for Authentication normalization."

gh issue create --title "Add Bitdefender threat detection sample log" \
  --body "Add a representative log entry from Bitdefender to sample_logs/bitdefender_threat.json. Use it to normalize into the Malware or Threat schema."

gh issue create --title "Add NGINX access log sample" \
  --body "Copy or generate a realistic NGINX access log entry and save it as sample_logs/nginx_access.json. This will be used to normalize into the WebActivity schema."

gh issue create --title "Add Zeek HTTP request log sample" \
  --body "Add a Zeek-formatted HTTP request log (either from Stratosphere or public GitHub datasets) and save it as sample_logs/zeek_http_request.json. It will be normalized to the NetworkActivity schema."

gh issue create --title "Normalize new sample logs to OCSF format" \
  --body "Write or extend normalization functions to convert sample logs in sample_logs/ into valid OCSF-formatted logs. Save them in normalized_logs/ and map them in the test suite."

gh issue create --title "Create simulate_ingest.py script for looping log ingestion" \
  --body "Write a Python script that reads each .json file in sample_logs/ with a delay to simulate real-time log forwarding. Output each log to stdout or to the dispatcher."

gh issue create --title "Add log tailing mode to simulate_ingest.py" \
  --body "Add an option to simulate_ingest.py that tails a log file, mimicking logs arriving in real-time (e.g., like a syslog agent)."

gh issue create --title "Feed simulated logs into dispatcher for real-time normalization" \
  --body "Update simulate_ingest.py to pass each log event to the dispatcher and normalize it. Write results to stdout or a separate normalized output directory."

# --- LABELS ---
echo "🏷️  Creating useful labels..."
gh label create "enhancement" --color "#a2eeef" --description "New feature or improvement"
gh label create "bug" --color "#d73a4a" --description "Something isn't working"
gh label create "good first issue" --color "#7057ff" --description "Ideal for first-time contributors"
gh label create "help wanted" --color "#008672" --description "Extra attention needed"
gh label create "question" --color "#d876e3" --description "Further clarification needed"

# --- OPTIONAL: Project Board ---
# echo "🗂️  Creating a GitHub project board..."
# gh project create --title "OCSF Log Normalizer" --format json

echo "🎉 All GitHub setup tasks completed!"
