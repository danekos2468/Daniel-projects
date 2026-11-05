"""
analyze_json_logs.py
EdoLearn University IT Security Log Analysis
Cybersecurity Analyst Practical Exercise
"""

import os
import json
import sys
from collections import Counter

REQUIRED_FIELDS = ["timestamp", "source_ip", "username", "event", "status", "application", "event_id"]

def load_and_validate_json(filepath):
    """
    Loads JSON file and validates record structure and required fields.
    Handles missing file, invalid JSON, and missing key/data errors cleanly.
    """
    if not os.path.exists(filepath):
        print(f"[ERROR] File '{filepath}' not found. Please check the file path.")
        return None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON file '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while opening '{filepath}': {e}")
        return None

    if not isinstance(data, list):
        print(f"[ERROR] Invalid data format in '{filepath}'. Expected a JSON array/list of event objects.")
        return None

    validated_events = []
    invalid_records = 0

    for idx, record in enumerate(data):
        if not isinstance(record, dict):
            print(f"[WARNING] Record #{idx+1} is not a valid JSON object. Skipping.")
            invalid_records += 1
            continue

        missing = [field for field in REQUIRED_FIELDS if field not in record or record[field] is None]
        if missing:
            print(f"[WARNING] Record EVT #{idx+1} is missing required field(s): {', '.join(missing)}. Skipping.")
            invalid_records += 1
            continue

        validated_events.append(record)

    if invalid_records > 0:
        print(f"[INFO] Total invalid/skipped records during validation: {invalid_records}\n")

    return validated_events

def generate_security_report(events):
    """
    Analyzes log records and prints formatted cybersecurity report.
    """
    if not events:
        print("[ERROR] No valid security events available for analysis.")
        return

    total_events = len(events)
    successful_logins = sum(1 for e in events if e["event"] == "login" and e["status"] == "success")
    failed_logins = sum(1 for e in events if e["event"] == "login" and e["status"] == "failed")
    access_denied = sum(1 for e in events if e["status"] == "denied")
    password_resets = sum(1 for e in events if e["event"] == "password_reset" or e["status"] == "requested")

    # Counts by Application, Event Type, and Status
    app_counts = Counter(e["application"] for e in events)
    event_counts = Counter(e["event"] for e in events)
    status_counts = Counter(e["status"] for e in events)

    # Failed logins by Source IP and Username (Sorted highest to lowest)
    failed_by_ip = Counter(e["source_ip"] for e in events if e["status"] == "failed")
    failed_by_user = Counter(e["username"] for e in events if e["status"] == "failed")

    print("==========================================================================")
    print("                EDOLEARN UNIVERSITY - IT SECURITY LOG REPORT             ")
    print("                        Semester Registration Rush                        ")
    print("==========================================================================")
    print(f"Total Logged Events Parsed : {total_events}")
    print(f"Successful Logins          : {successful_logins}")
    print(f"Failed Logins              : {failed_logins}")
    print(f"Access-Denied Events       : {access_denied}")
    print(f"Password-Reset Requests    : {password_resets}")
    print("--------------------------------------------------------------------------")

    print("\n[+] EVENTS BY APPLICATION:")
    for app, count in app_counts.most_common():
        print(f"  - {app:<25}: {count}")

    print("\n[+] EVENTS BY EVENT TYPE:")
    for ev_type, count in event_counts.most_common():
        print(f"  - {ev_type:<25}: {count}")

    print("\n[+] EVENTS BY STATUS:")
    for st, count in status_counts.most_common():
        print(f"  - {st:<25}: {count}")

    print("\n[+] FAILED LOGINS BY SOURCE IP (Sorted Highest to Lowest):")
    print(f"  {'Source IP':<18} {'Failed Count':<14} {'Flag Status'}")
    print("  " + "-" * 45)
    for ip, count in failed_by_ip.most_common():
        flag = "REVIEW (>= 5 Failed Logins)" if count >= 5 else "NORMAL"
        print(f"  {ip:<18} {count:<14} {flag}")

    print("\n[+] FAILED LOGINS BY USERNAME (Sorted Highest to Lowest):")
    print(f"  {'Username':<22} {'Failed Count'}")
    print("  " + "-" * 35)
    for user, count in failed_by_user.most_common():
        print(f"  {user:<22} {count}")

    print("\n--------------------------------------------------------------------------")
    print("[NOTE FOR ANALYST REVIEW]")
    print("Repeated authentication failures serve as key indicators for investigation,")
    print("not absolute proof of an attack. Network latency, user error, or misconfigured")
    print("saved credentials can generate identical failure signatures.")
    print("AUTOMATED ACTION POLICY: Do not block IPs or disable accounts automatically;")
    print("any remediation action requires human approval from an authorized analyst.")
    print("==========================================================================\n")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "security_events.json"
    events = load_and_validate_json(filepath)
    if events:
        generate_security_report(events)
