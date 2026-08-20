"""
Natural-language -> SPL translator and investigation chain, built and
validated against synthetic Splunk data before migrating to real endpoint
telemetry (see hunt_engine.py for the real-data version).

Design: a deterministic regex parser handles well-defined question
patterns with 100% reliability; only questions matching no known pattern
fall back to a locally-hosted LLM (Llama 3.2 via Ollama). Every
LLM-generated query is checked against a destructive-command blocklist
before it is allowed to run.
"""

import os
import re
import requests
import json

SPLUNK_HOST = "https://localhost:8089"
SPLUNK_USER = "hafsa"
SPLUNK_PASS = os.environ.get("SPLUNK_PASS")

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"

SPL_SYSTEM_PROMPT = """You are a Splunk SPL query generator for a security log index called threat_hunt.

The index has these fields:
- event_type: auth, network, or process
- hostname: hostname like host-001
- user: username like user7
- src_ip, dst_ip: IP addresses
- dst_port: numeric port
- bytes_sent: numeric
- auth_success: true or false
- process_name: e.g. powershell.exe, cmd.exe
- detail: text description

Convert the user's question into ONE valid SPL search command starting with
"search index=threat_hunt". Output ONLY the SPL command, nothing else -- no
explanation, no markdown formatting, no backticks.

Pay close attention to any specific host names, usernames, ports, or process
names mentioned in the question -- use exactly those values, do not reuse
values from the examples below.

Examples:
Question: "find any unusual activity on host-021"
SPL: search index=threat_hunt hostname=host-021 | sort timestamp

Question: "what happened on host-035"
SPL: search index=threat_hunt hostname=host-035 | sort timestamp

Question: "show failed logins for user7"
SPL: search index=threat_hunt event_type=auth user=user7 auth_success=false

Question: "find powershell executions"
SPL: search index=threat_hunt event_type=process process_name=powershell.exe

Question: "connections to port 8080"
SPL: search index=threat_hunt event_type=network dst_port=8080

Question: "users with more than 2 failed logins"
SPL: search index=threat_hunt event_type=auth auth_success=false | stats count by user, src_ip | where count>=2 | sort -count
"""

DANGEROUS_SPL_COMMANDS = ["delete", "outputlookup", "script", "sendemail",
                          "collect", "| run", "map "]


def parse_query_to_spl(question: str) -> str:
    """Deterministic regex-based translation for well-defined question patterns."""
    q = question.lower()

    m = re.search(r"(?:more than|over|>)\s*(\d+)\s*(?:failed|fail)", q)
    if m or "failed login" in q or "failed logon" in q:
        threshold = int(m.group(1)) if m else 1
        return (f'search index=threat_hunt event_type=auth auth_success=false '
                f'| stats count by user, src_ip | where count>={threshold} | sort -count')

    if "powershell" in q:
        return 'search index=threat_hunt event_type=process process_name=powershell.exe'

    m = re.search(r"port\s*(\d+)", q)
    if m:
        return f'search index=threat_hunt event_type=network dst_port={m.group(1)}'

    m = re.search(r"\buser(\d+)\b", q)
    if m:
        return f'search index=threat_hunt user=user{m.group(1)} | sort timestamp'

    return f'search index=threat_hunt {question}'


def llm_parse_query_to_spl(question: str) -> str:
    """Ask the local LLM to translate the question into SPL."""
    prompt = f"{SPL_SYSTEM_PROMPT}\n\nQuestion: \"{question}\"\nSPL:"

    resp = requests.post(OLLAMA_URL, json={
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1}
    })
    resp.raise_for_status()
    spl = resp.json()["response"].strip()

    if not spl.lower().startswith("search index=threat_hunt"):
        print(f"[WARNING] LLM output looked wrong ('{spl[:60]}...'), falling back to regex parser")
        return parse_query_to_spl(question)

    return spl


def is_spl_safe(spl: str) -> bool:
    """Reject any generated SPL containing destructive/dangerous commands."""
    lowered = spl.lower()
    return not any(bad in lowered for bad in DANGEROUS_SPL_COMMANDS)


def run_spl_search(spl: str):
    """Sends SPL to Splunk's export endpoint and returns results as a list of dicts."""
    url = f"{SPLUNK_HOST}/services/search/jobs/export"
    resp = requests.post(
        url,
        auth=(SPLUNK_USER, SPLUNK_PASS),
        data={"search": spl, "output_mode": "json"},
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


def hunt(question: str):
    """
    Hybrid dispatch: try the deterministic regex parser first (100%
    reliable for known patterns, especially aggregation/threshold
    questions which small LLMs handle unreliably). Only fall back to the
    LLM for questions the regex parser doesn't recognize.
    """
    regex_spl = parse_query_to_spl(question)
    is_generic_fallback = regex_spl == f'search index=threat_hunt {question}'

    if not is_generic_fallback:
        spl = regex_spl
        print(f"\nQ: {question}")
        print(f"[Matched known pattern -- regex parser used]")
        print(f"Translated SPL: {spl}")
    else:
        spl = llm_parse_query_to_spl(question)
        print(f"\nQ: {question}")
        print(f"[No known pattern matched -- LLM used]")
        print(f"Translated SPL: {spl}")

    if not is_spl_safe(spl):
        print("[BLOCKED] Generated SPL contained a disallowed command. Refusing to run it.")
        return []

    results = run_spl_search(spl)
    print(f"Results: {len(results)} rows")
    for r in results[:5]:
        print(r)
    return results


def hunt_chain(verbose=True):
    """
    Multi-step automated investigation on the synthetic dataset: follows a
    lateral-movement trail from initial credential testing through to a
    possible C2 connection, without the analyst needing to ask each
    question manually.
    """
    findings = {"steps": []}

    if verbose:
        print("\n=== STEP 1: Looking for accounts with repeated failed logins ===")
    spl1 = ('search index=threat_hunt event_type=auth auth_success=false '
            '| stats count by user, src_ip | where count>=2 | sort -count')
    step1_results = run_spl_search(spl1)
    findings["steps"].append({"step": "failed_login_recon", "spl": spl1, "results": step1_results})
    if verbose:
        print(f"SPL: {spl1}")
        print(f"Found {len(step1_results)} suspicious account(s): {step1_results}")

    if not step1_results:
        if verbose:
            print("No suspicious accounts found -- chain stops here.")
        return findings

    suspect_user = step1_results[0]["user"]
    if verbose:
        print(f"\n=== STEP 2: Checking if '{suspect_user}' had a successful login too ===")
    spl2 = (f'search index=threat_hunt event_type=auth user={suspect_user} '
            f'auth_success=true | sort timestamp')
    step2_results = run_spl_search(spl2)
    findings["steps"].append({"step": "successful_login_check", "spl": spl2, "results": step2_results})
    if verbose:
        print(f"SPL: {spl2}")
        print(f"Successful logins for {suspect_user}: {step2_results}")

    if not step2_results:
        if verbose:
            print("No successful login found -- likely a failed attack attempt. Chain stops here.")
        return findings

    compromised_host = step2_results[0]["hostname"]
    if verbose:
        print(f"\n=== STEP 3: Checking what ran on '{compromised_host}' after login ===")
    spl3 = f'search index=threat_hunt event_type=process hostname={compromised_host} | sort timestamp'
    step3_results = run_spl_search(spl3)
    findings["steps"].append({"step": "post_login_process_check", "spl": spl3, "results": step3_results})
    if verbose:
        print(f"SPL: {spl3}")
        print(f"Processes on {compromised_host}: {step3_results}")

    if verbose:
        print(f"\n=== STEP 4: Checking network connections from '{compromised_host}' ===")
    spl4 = f'search index=threat_hunt event_type=network hostname={compromised_host} | sort timestamp'
    step4_results = run_spl_search(spl4)
    findings["steps"].append({"step": "network_connection_check", "spl": spl4, "results": step4_results})
    if verbose:
        print(f"SPL: {spl4}")
        print(f"Connections from {compromised_host}: {step4_results}")

    if verbose:
        print("\n=== SUMMARY ===")
        print(f"Suspicious user: {suspect_user}")
        print(f"Compromised host: {compromised_host}")
        print(f"Processes observed: {[p.get('process_name') for p in step3_results]}")
        print(f"Outbound connections: {[(c.get('dst_ip'), c.get('dst_port')) for c in step4_results]}")

    findings["summary"] = {
        "suspicious_user": suspect_user,
        "compromised_host": compromised_host,
        "process_count": len(step3_results),
        "connection_count": len(step4_results),
    }
    return findings


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    print("=== LLM Threat Hunting (synthetic data) — type a question, 'chain' for auto-investigation, or 'quit' to exit ===")
    while True:
        q = input("\nHunt query> ").strip()
        if q.lower() in ("quit", "exit"):
            break
        if q.lower() == "chain":
            hunt_chain()
        elif q:
            hunt(q)
