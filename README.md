# LLM-Based Threat Hunting for SOC Environments

A natural-language threat hunting engine built on top of Splunk. Ask a plain-English
question — no SPL required — and get a real, executed Splunk search back, with results.
Also runs a fully automated multi-step investigation chain that follows a suspicious
login attempt through to a compromise and any follow-on activity.

Built and validated in two stages:
1. **Synthetic prototype** (`generate_logs.py` + `nl_query_splunk.py`) — a controlled
   dataset with a planted lateral-movement attack scenario, used to prove the
   architecture before touching real data.
2. **Real telemetry** (`hunt_engine.py` + `dashboard.py`) — the same architecture
   re-pointed at live Windows Security Event Log and Sysmon data from an actual
   monitored endpoint.

## What it does

- **Natural-language query translation** — a hybrid engine: a deterministic regex
  parser handles well-defined question patterns with 100% reliability; a locally-hosted
  LLM (Llama 3.2, via Ollama) handles open-ended questions the parser doesn't recognize.
- **Safety guardrail** — every LLM-generated query is checked against a blocklist of
  destructive SPL commands before it's allowed to run.
- **Automated investigation chain** — one click walks: repeated failed logins →
  successful login → correlated process activity → correlated network connections,
  recovering a full attack narrative without an analyst writing a single query.
- **Adjustable time range** — Last 24 hours / 7 days / 30 days / All time, both for
  single questions and the full investigation.
- **Interactive dashboard** — built with Streamlit, showing the generated SPL alongside
  results for full transparency.

## Files

| File | Purpose |
|---|---|
| `generate_logs.py` | Generates synthetic SOC telemetry (auth/network/process events) with a planted attack scenario. Prototype stage only. |
| `nl_query_splunk.py` | Hybrid regex + LLM query engine and investigation chain, built against the synthetic dataset. |
| `hunt_engine.py` | The real-data engine: queries live Windows Security Event Log + Sysmon telemetry via Splunk's REST API. **This is the main, current engine.** |
| `dashboard.py` | Streamlit dashboard — the analyst-facing UI, built on top of `hunt_engine.py`. |
| `requirements.txt` | Python dependencies. |

## Setup

### 1. Prerequisites
- **Splunk Enterprise** (free trial license is enough) — running and reachable at
  `https://localhost:8089` (REST API) and `http://localhost:8000` (web UI).
- **Ollama** — for serving the local LLM:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull llama3.2:1b
  ```
- **Python 3.10+**

### 2. Install dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Set your Splunk credentials
```bash
export SPLUNK_PASS='your-splunk-password'
```
(Add this to `~/.bashrc` to persist it across terminal sessions.)

Update `SPLUNK_USER` at the top of `hunt_engine.py` / `nl_query_splunk.py` if your
Splunk admin username isn't `hafsa`.

### 4. Make sure Ollama is running
```bash
sudo systemctl enable ollama
sudo systemctl start ollama
```

### 5a. Run against real telemetry (main path)
Requires Splunk already ingesting Windows Security Event Log (`EventCode 4624`/`4625`)
and Sysmon (`WinEventLog:Microsoft-Windows-Sysmon/Operational`) data — e.g. via the
Splunk Universal Forwarder on a monitored Windows host.

```bash
python3 hunt_engine.py          # CLI: runs the investigation chain once
streamlit run dashboard.py      # Web UI
```

### 5b. Run against synthetic data (prototype path)
```bash
python3 generate_logs.py
sudo /opt/splunk/bin/splunk add index threat_hunt -auth <user>:<pass>
sudo /opt/splunk/bin/splunk add oneshot logs.json -index threat_hunt -sourcetype _json -auth <user>:<pass>
python3 nl_query_splunk.py      # interactive CLI — type a question, 'chain', or 'quit'
```

## Architecture

```
Natural-language question
        │
        ▼
┌───────────────────┐      no match       ┌──────────────────────┐
│  Regex parser       │ ──────────────────▶│  Local LLM (Ollama)   │
│  (known patterns)   │                     │  Llama 3.2, 1B params │
└───────────────────┘                     └──────────────────────┘
        │                                            │
        └───────────────────┬────────────────────────┘
                             ▼
                  Safety check (blocklist)
                             │
                             ▼
                  Splunk REST API (SPL search)
                             │
                             ▼
                    Results → Dashboard
```

## Known limitations

- The LLM fallback is reliable for simple single-condition lookups (e.g. "find
  powershell executions") but less reliable for open-ended, multi-step reasoning
  questions — a known limitation of small (1B-parameter) local models.
- The multi-step investigation chain follows a fixed sequence rather than reasoning
  dynamically about what to check next; a genuinely agentic version would use the LLM
  to decide the next investigative step based on prior findings.
- Validated against a single monitored endpoint; multi-host lateral-movement detection
  (via Splunk Universal Forwarders on additional machines) is a natural next step.

## Real bugs fixed along the way (worth knowing if you extend this)

- **Splunk's reserved `host` field** — a custom field also named `host` gets silently
  overwritten by Splunk's own metadata. Renamed to `hostname` throughout.
- **Windows' multivalue `Account_Name` field** — contains both real accounts and noisy
  machine accounts (e.g. `WIN$`) on the same event; naive filtering wipes out entire
  events. Fixed with `mvfilter` to clean the field before any event-level filtering.
- **Splunk's `xmlkv` doesn't reliably parse Sysmon's attribute-based XML fields** —
  switched to targeted `rex` regex extraction against the raw event text instead.

## License

Personal / academic project. No license specified — add one if you intend to share
or reuse this code publicly.
