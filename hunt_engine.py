"""
Real-telemetry threat hunting engine: queries live Windows Security Event
Log (authentication) and Sysmon (process/network) data via Splunk's REST
API. This is the production version of the pipeline, validated against
actual endpoint data rather than synthetic events.

Two hard-won fixes baked into this file (see README for full details):
  1. CLEAN_ACCOUNT_NAME -- Windows' Account_Name field is multivalue and
     contains both real user accounts and noisy machine/service accounts
     on the same event. mvfilter is used to clean the field itself before
     any event-level filtering, since a naive Account_Name!="value" filter
     excludes the WHOLE event if any value in the multivalue field matches.
  2. REX extraction -- Splunk's built-in xmlkv command does not reliably
     parse Sysmon's attribute-based XML Data fields, so targeted regex
     extraction against the raw event text is used instead.
"""

import os
import re
import requests
import json
from datetime import datetime

SPLUNK_HOST = "https://localhost:8089"
SPLUNK_USER = "hafsa"
SPLUNK_PASS = os.environ.get("SPLUNK_PASS")

SECURITY_SOURCE = 'source="WinEventLog:Security"'
SYSMON_SOURCE = 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"'

# Windows logs the machine account (e.g. WIN$) and built-in system accounts
# alongside real human accounts in the SAME multivalue Account_Name field.
# These accounts are constantly active for background Kerberos/service
# activity and will always dominate a raw "most failed logins" ranking,
# burying genuine human activity -- so they're cleaned out at the field
# level with mvfilter, the same way a real detection rule would.
CLEAN_ACCOUNT_NAME = (
    '| eval Account_Name=mvfilter(Account_Name!="SYSTEM" AND Account_Name!="ANONYMOUS LOGON" '
    'AND Account_Name!="LOCAL SERVICE" AND Account_Name!="NETWORK SERVICE" AND Account_Name!="-" '
    'AND NOT match(Account_Name, "\\$$")) '
    '| eval Account_Name=mvindex(Account_Name,0) '
    '| where isnotnull(Account_Name)'
)

REX = {
    "Image": "| rex field=_raw \"Name='Image'>(?<Image>[^<]*)</Data>\"",
    "CommandLine": "| rex field=_raw \"Name='CommandLine'>(?<CommandLine>[^<]*)</Data>\"",
    "User": "| rex field=_raw \"Name='User'>(?<User>[^<]*)</Data>\"",
    "SourceIp": "| rex field=_raw \"Name='SourceIp'>(?<SourceIp>[^<]*)</Data>\"",
    "DestinationIp": "| rex field=_raw \"Name='DestinationIp'>(?<DestinationIp>[^<]*)</Data>\"",
    "DestinationPort": "| rex field=_raw \"Name='DestinationPort'>(?<DestinationPort>[^<]*)</Data>\"",
}

# Human-friendly time range options -> Splunk's REST API time params.
# The REST API, unlike the Splunk web UI's time picker, does not default
# to any time restriction unless explicitly passed -- so this must be set
# on every search, or results silently span "all time."
TIME_RANGES = {
    "Last 24 hours": {"earliest_time": "-24h", "latest_time": "now"},
    "Last 7 days": {"earliest_time": "-7d", "latest_time": "now"},
    "Last 30 days": {"earliest_time": "-30d", "latest_time": "now"},
    "All time": {"earliest_time": "0", "latest_time": "now"},
}


def build_rex_chain(*fields):
    return " ".join(REX[f] for f in fields if f in REX)


def run_spl_search(spl: str, time_range: str = "All time"):
    """
    time_range: one of the keys in TIME_RANGES. Passed as separate
    earliest_time/latest_time params to Splunk's export API.
    """
    bounds = TIME_RANGES.get(time_range, TIME_RANGES["All time"])

    url = f"{SPLUNK_HOST}/services/search/jobs/export"
    resp = requests.post(
        url,
        auth=(SPLUNK_USER, SPLUNK_PASS),
        data={
            "search": spl,
            "output_mode": "json",
            "earliest_time": bounds["earliest_time"],
            "latest_time": bounds["latest_time"],
        },
        verify=False,
        stream=True,
    )
    resp.raise_for_status()

    results = []
    for line in resp.iter_lines():
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "result" in obj:
                results.append(obj["result"])
        except json.JSONDecodeError:
            continue
    return results


def parse_query_to_spl(question: str) -> str:
    q = question.lower()

    m = re.search(r"(?:more than|over|>)\s*(\d+)\s*(?:failed|fail)", q)
    if m or "failed login" in q or "failed logon" in q:
        threshold = int(m.group(1)) if m else 1
        return (f'search index=main {SECURITY_SOURCE} EventCode=4625 {CLEAN_ACCOUNT_NAME} '
                f'| stats count by Account_Name, src_ip | where count>={threshold} | sort -count')

    if "successful login" in q or "successful logon" in q:
        return (f'search index=main {SECURITY_SOURCE} EventCode=4624 {CLEAN_ACCOUNT_NAME} '
                f'| table _time, Account_Name, src_ip, Logon_Type | sort -_time')

    for proc in ["powershell", "cmd.exe", "wmic", "python", "svchost", "chrome", "msedge"]:
        key = proc if proc.endswith(".exe") else proc + ".exe"
        if proc.replace(".exe", "") in q:
            rex_chain = build_rex_chain("Image", "CommandLine", "User")
            return (f'search index=main {SYSMON_SOURCE} EventID=1 {rex_chain} '
                    f'| search Image="*{key}*" '
                    f'| table _time, Image, CommandLine, User | sort -_time')

    if "double extension" in q or "disguised" in q or "suspicious file" in q:
        rex_chain = build_rex_chain("Image", "CommandLine", "User")
        return (f'search index=main {SYSMON_SOURCE} EventID=1 {rex_chain} '
                f'| regex Image="\\.\\w+\\.exe$" '
                f'| table _time, Image, CommandLine, User | sort -_time')

    m = re.search(r"port\s*(\d+)", q)
    if m:
        rex_chain = build_rex_chain("Image", "SourceIp", "DestinationIp", "DestinationPort")
        return (f'search index=main {SYSMON_SOURCE} EventID=3 {rex_chain} '
                f'| search DestinationPort={m.group(1)} '
                f'| table _time, Image, SourceIp, DestinationIp, DestinationPort | sort -_time')

    if "connection" in q or "network" in q or "outbound" in q:
        rex_chain = build_rex_chain("Image", "SourceIp", "DestinationIp", "DestinationPort")
        return (f'search index=main {SYSMON_SOURCE} EventID=3 {rex_chain} '
                f'| where isnotnull(DestinationIp) AND DestinationIp!="" '
                f'| table _time, Image, SourceIp, DestinationIp, DestinationPort | sort -_time')

    rex_chain = build_rex_chain("Image", "CommandLine", "User")
    return (f'search index=main {SYSMON_SOURCE} {rex_chain} {question} '
            f'| table _time, EventID, Image, CommandLine, User')


def hunt_chain(verbose=True, min_failed=3, window_minutes=15, time_range="All time"):
    """
    Real-data investigation, adapted for a SINGLE monitored host:
    1. Find accounts with repeated failed logins (Security log, EventCode 4625)
    2. Check for a successful login (4624) for that account
    3. Within a time window around the suspicious activity, check what
       processes ran (Sysmon EventID=1)
    4. Within the same window, check outbound network connections (Sysmon EventID=3)

    This is TIME-based correlation rather than host-hopping, since there's
    one endpoint being monitored -- a legitimate, commonly used real-world
    hunting pattern in its own right.
    """
    findings = {"steps": []}

    if verbose:
        print(f"\n=== STEP 1: Accounts with {min_failed}+ failed logins (excluding noisy system accounts) ===")
    spl1 = (f'search index=main {SECURITY_SOURCE} EventCode=4625 {CLEAN_ACCOUNT_NAME} '
            f'| stats count, latest(_time) as last_seen by Account_Name, src_ip '
            f'| where count>={min_failed} | sort -count')
    step1 = run_spl_search(spl1, time_range=time_range)
    findings["steps"].append({"step": "failed_login_recon", "spl": spl1, "results": step1})
    if verbose:
        print(f"SPL: {spl1}\nFound: {step1}")

    if not step1:
        if verbose:
            print("No suspicious accounts found.")
        return findings

    account = step1[0]["Account_Name"]
    center_time = step1[0]["last_seen"]

    if verbose:
        print(f"\n=== STEP 2: Checking for a successful login for '{account}' ===")
    spl2 = (f'search index=main {SECURITY_SOURCE} EventCode=4624 Account_Name="{account}" '
            f'| table _time, Account_Name, src_ip, Logon_Type | sort _time')
    step2 = run_spl_search(spl2, time_range=time_range)
    findings["steps"].append({"step": "successful_login_check", "spl": spl2, "results": step2})
    if verbose:
        print(f"SPL: {spl2}\nFound: {step2}")

    try:
        center_epoch = float(center_time)
    except (ValueError, TypeError):
        center_epoch = None

    if center_epoch:
        earliest = datetime.utcfromtimestamp(center_epoch).strftime("%m/%d/%Y:%H:%M:%S")
        latest = datetime.utcfromtimestamp(center_epoch + window_minutes * 60).strftime("%m/%d/%Y:%H:%M:%S")
        window_bounds = f'earliest="{earliest}" latest="{latest}"'
    else:
        window_bounds = ""

    if verbose:
        print(f"\n=== STEP 3: Processes launched in the {window_minutes}-min window after the activity ===")
    rex_chain = build_rex_chain("Image", "CommandLine", "User")
    spl3 = (f'search index=main {SYSMON_SOURCE} EventID=1 {window_bounds} {rex_chain} '
            f'| table _time, Image, CommandLine, User | sort _time')
    step3 = run_spl_search(spl3, time_range="All time")
    findings["steps"].append({"step": "correlated_process_check", "spl": spl3, "results": step3})
    if verbose:
        print(f"SPL: {spl3}\nFound {len(step3)} process event(s)")

    if verbose:
        print(f"\n=== STEP 4: Network connections in the same window ===")
    rex_chain2 = build_rex_chain("Image", "SourceIp", "DestinationIp", "DestinationPort")
    spl4 = (f'search index=main {SYSMON_SOURCE} EventID=3 {window_bounds} {rex_chain2} '
            f'| where isnotnull(DestinationIp) AND DestinationIp!="" '
            f'| table _time, Image, SourceIp, DestinationIp, DestinationPort | sort _time')
    step4 = run_spl_search(spl4, time_range="All time")
    findings["steps"].append({"step": "correlated_network_check", "spl": spl4, "results": step4})
    if verbose:
        print(f"SPL: {spl4}\nFound {len(step4)} connection(s)")

    findings["summary"] = {
        "suspicious_account": account,
        "successful_login_found": len(step2) > 0,
        "process_count_in_window": len(step3),
        "connection_count_in_window": len(step4),
    }
    if verbose:
        print("\n=== SUMMARY ===")
        print(findings["summary"])

    return findings


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    hunt_chain(time_range="Last 7 days")
