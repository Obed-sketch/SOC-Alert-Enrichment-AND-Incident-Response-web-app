import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
import streamlit as st

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "soc_audit.db")
VT_BASE = "https://www.virustotal.com/api/v3"

st.set_page_config(page_title="SOC Alert Enrichment & Response", page_icon="🛡️", layout="wide")

# ----------------------------- Persistence -----------------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                vm_id TEXT,
                alert_id TEXT,
                verdict TEXT,
                malicious INTEGER,
                suspicious INTEGER,
                total_engines INTEGER,
                action TEXT,
                action_result TEXT,
                raw_json TEXT
            )
        """)
        conn.commit()

def audit_event(data: Dict[str, Any]):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO events
            (created_at, indicator, indicator_type, vm_id, alert_id, verdict,
             malicious, suspicious, total_engines, action, action_result, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            data.get("indicator", ""), data.get("indicator_type", ""),
            data.get("vm_id", ""), data.get("alert_id", ""),
            data.get("verdict", ""), int(data.get("malicious", 0)),
            int(data.get("suspicious", 0)), int(data.get("total_engines", 0)),
            data.get("action", ""), data.get("action_result", ""),
            json.dumps(data, default=str)
        ))
        conn.commit()

def load_events(limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

# ----------------------------- Validation -----------------------------
def classify_indicator(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return "file_hash"
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        raise ValueError("Enter a valid IPv4/IPv6 address or MD5, SHA-1, or SHA-256 hash.")

# ----------------------------- Threat intel -----------------------------
def virustotal_lookup(indicator: str, indicator_type: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        raise RuntimeError("Add your VirusTotal API key in the sidebar.")
    endpoint = "ip_addresses" if indicator_type == "ip" else "files"
    url = f"{VT_BASE}/{endpoint}/{indicator}"
    response = requests.get(url, headers={"x-apikey": api_key}, timeout=25)
    if response.status_code == 404:
        raise RuntimeError("VirusTotal has no report for this indicator.")
    if response.status_code == 401:
        raise RuntimeError("VirusTotal rejected the API key. Check your key.")
    if response.status_code == 429:
        raise RuntimeError("VirusTotal rate limit reached. Try again later.")
    response.raise_for_status()
    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_MALICIOUS_DETECTIONS"
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "verdict": verdict,
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "permalink": f"https://www.virustotal.com/gui/{'ip-address' if indicator_type == 'ip' else 'file'}/{indicator}",
    }

# ----------------------------- Response integrations -----------------------------
def post_webhook(url: str, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not url:
        raise RuntimeError("Webhook URL is not configured.")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(url, json=payload, headers=headers, timeout=20)
    response.raise_for_status()
    return {"http_status": response.status_code, "body": response.text[:1000]}

def open_ticket(enrichment: Dict[str, Any], alert: Dict[str, Any], url: str, token: str):
    payload = {
        "title": f"[SOC] {enrichment['verdict']} indicator: {enrichment['indicator']}",
        "description": (
            f"Automated threat-intelligence enrichment.\n"
            f"Indicator: {enrichment['indicator']} ({enrichment['indicator_type']})\n"
            f"VirusTotal detections: {enrichment['malicious']} malicious / "
            f"{enrichment['total_engines']} engines; suspicious: {enrichment['suspicious']}\n"
            f"VM: {alert.get('vm_id') or 'not supplied'} | SIEM alert: {alert.get('alert_id') or 'not supplied'}\n"
            f"Report: {enrichment['permalink']}\n"
            "Please validate the alert and follow incident-response procedures."
        ),
        "severity": "high" if enrichment["malicious"] >= 5 else "medium",
        "source": "SOC Alert Enrichment App",
        "alert": alert,
        "enrichment": enrichment,
    }
    return post_webhook(url, token, payload)

def isolate_vm(enrichment: Dict[str, Any], alert: Dict[str, Any], url: str, token: str):
    vm_id = alert.get("vm_id")
    if not vm_id:
        raise RuntimeError("Cannot isolate: the SIEM event did not include vm_id.")
    payload = {
        "action": "isolate_vm",
        "vm_id": vm_id,
        "reason": f"VirusTotal malicious detections: {enrichment['malicious']}/{enrichment['total_engines']}",
        "indicator": enrichment["indicator"],
        "alert_id": alert.get("alert_id"),
        "source": "SOC Alert Enrichment App",
    }
    return post_webhook(url, token, payload)

# ----------------------------- UI -----------------------------
init_db()
st.title("🛡️ SOC Alert Enrichment & Response")
st.caption("Enrich SIEM indicators with VirusTotal, document findings, and route approved response actions.")

with st.sidebar:
    st.header("Integration settings")
    vt_key = st.text_input("VirusTotal API key", type="password", value=os.getenv("VT_API_KEY", ""))
    st.caption("Your key is used server-side for API requests. Do not commit it to source control.")
    st.divider()
    ticket_url = st.text_input("Ticketing webhook URL", value=os.getenv("TICKET_WEBHOOK_URL", ""))
    ticket_token = st.text_input("Ticketing bearer token", type="password", value=os.getenv("TICKET_WEBHOOK_TOKEN", ""))
    isolate_url = st.text_input("EDR / VM isolation webhook URL", value=os.getenv("ISOLATION_WEBHOOK_URL", ""))
    isolate_token = st.text_input("Isolation bearer token", type="password", value=os.getenv("ISOLATION_WEBHOOK_TOKEN", ""))
    st.divider()
    st.subheader("Response policy")
    threshold = st.number_input("Malicious detection threshold", min_value=1, max_value=100, value=1)
    auto_ticket = st.checkbox("Automatically open ticket at/above threshold", value=False)
    auto_isolate = st.checkbox("Allow automatic VM isolation", value=False,
                               help="High-impact action. Enable only after validating your webhook and testing in a lab.")
    require_confirmation = st.checkbox("Require manual confirmation before isolation", value=True)
    st.warning("Isolation is a disruptive containment action. Use a least-privilege, authenticated EDR endpoint and test with a lab VM.")

tab_analyze, tab_siem, tab_audit, tab_help = st.tabs(
    ["Analyze indicator", "SIEM event intake", "Audit log", "Setup & API contract"]
)

def process_indicator(indicator: str, alert: Dict[str, Any], approved_isolation: bool = False):
    # Automatic containment is permitted only when explicitly enabled and the
    # analyst has disabled the extra confirmation requirement in the sidebar.
    approved_isolation = approved_isolation or (auto_isolate and not require_confirmation)
    indicator = indicator.strip()
    kind = classify_indicator(indicator)
    result = virustotal_lookup(indicator, kind, vt_key)
    st.session_state["last_result"] = result
    st.session_state["last_alert"] = alert
    action = "none"
    action_result = "No response action taken."
    meets_threshold = result["malicious"] >= threshold

    if meets_threshold and auto_ticket and ticket_url:
        try:
            ticket_result = open_ticket(result, alert, ticket_url, ticket_token)
            action = "ticket"
            action_result = f"Ticket webhook accepted (HTTP {ticket_result['http_status']})."
        except Exception as exc:
            action = "ticket_failed"
            action_result = f"Ticket webhook failed: {exc}"

    if meets_threshold and auto_isolate and approved_isolation and isolate_url:
        try:
            isolate_result = isolate_vm(result, alert, isolate_url, isolate_token)
            action = "isolation_requested" if action == "none" else action + "+isolation_requested"
            action_result += f" Isolation webhook accepted (HTTP {isolate_result['http_status']})."
        except Exception as exc:
            action += "+isolation_failed"
            action_result += f" Isolation failed: {exc}"

    result["action"] = action
    result["action_result"] = action_result
    result["vm_id"] = alert.get("vm_id", "")
    result["alert_id"] = alert.get("alert_id", "")
    audit_event(result)
    return result

with tab_analyze:
    st.subheader("Manual indicator lookup")
    c1, c2 = st.columns([3, 1])
    with c1:
        indicator = st.text_input("Suspicious IP address or file hash", placeholder="8.8.8.8 or SHA-256 hash")
    with c2:
        vm_id = st.text_input("Affected VM ID (optional)", placeholder="vm-123")
    alert_id = st.text_input("SIEM alert ID (optional)", placeholder="ALERT-00042", key="manual_alert")
    if st.button("Enrich indicator", type="primary"):
        if not indicator:
            st.error("Enter an IP address or file hash.")
        else:
            try:
                with st.spinner("Querying VirusTotal..."):
                    result = process_indicator(indicator, {"vm_id": vm_id, "alert_id": alert_id})
                st.success("Enrichment complete.")
                st.session_state["last_result"] = result
            except Exception as exc:
                st.error(str(exc))

    result = st.session_state.get("last_result")
    if result:
        st.divider()
        st.subheader("Threat intelligence result")
        color = "red" if result["verdict"] == "MALICIOUS" else "orange" if result["verdict"] == "SUSPICIOUS" else "green"
        st.markdown(f"### :{color}[{result['verdict']}]")
        metrics = st.columns(4)
        metrics[0].metric("Malicious", result["malicious"])
        metrics[1].metric("Suspicious", result["suspicious"])
        metrics[2].metric("Harmless", result["harmless"])
        metrics[3].metric("Engines reporting", result["total_engines"])
        st.write(f"**Indicator:** `{result['indicator']}`")
        st.write(f"**Type:** {result['indicator_type']} · **Reputation:** {result.get('reputation')}")
        st.link_button("Open VirusTotal report", result["permalink"])
        st.info(result.get("action_result", "No response action taken."))

        alert_for_result = st.session_state.get("last_alert", {})
        meets = result["malicious"] >= threshold
        if meets:
            st.warning("This result meets the configured malicious-detection threshold.")
            confirm = st.checkbox("I have validated the target VM and approve an isolation request.", key="isolation_confirm")
            if st.button("Request VM isolation", disabled=not (confirm and isolate_url)):
                try:
                    response = isolate_vm(result, alert_for_result, isolate_url, isolate_token)
                    audit_event({**result, "vm_id": alert_for_result.get("vm_id", ""),
                                 "alert_id": alert_for_result.get("alert_id", ""),
                                 "action": "manual_isolation_requested",
                                 "action_result": f"HTTP {response['http_status']}"})
                    st.success(f"Isolation request sent (HTTP {response['http_status']}).")
                except Exception as exc:
                    st.error(f"Isolation request failed: {exc}")
        if st.button("Open ticket now", disabled=not bool(ticket_url)):
            try:
                response = open_ticket(result, alert_for_result, ticket_url, ticket_token)
                audit_event({**result, "vm_id": alert_for_result.get("vm_id", ""),
                             "alert_id": alert_for_result.get("alert_id", ""),
                             "action": "manual_ticket",
                             "action_result": f"HTTP {response['http_status']}"})
                st.success(f"Ticket request sent (HTTP {response['http_status']}).")
            except Exception as exc:
                st.error(f"Ticket creation failed: {exc}")

with tab_siem:
    st.subheader("Ingest a SIEM alert")
    st.write("Paste a normalized JSON event from your SIEM, or send the same structure to an API adapter you build around this function.")
    sample = {
        "alert_id": "ALERT-2026-0001",
        "indicator": "8.8.8.8",
        "vm_id": "lab-vm-01",
        "source": "Example SIEM",
        "severity": "high"
    }
    raw = st.text_area("SIEM event JSON", value=json.dumps(sample, indent=2), height=220)
    if st.button("Process SIEM event", type="primary"):
        try:
            event = json.loads(raw)
            if not isinstance(event, dict):
                raise ValueError("The SIEM payload must be a JSON object.")
            if not event.get("indicator"):
                raise ValueError("SIEM payload must include 'indicator'.")
            with st.spinner("Enriching SIEM event..."):
                result = process_indicator(event["indicator"], event)
            st.success(f"Processed {event.get('alert_id', 'SIEM event')}: {result['verdict']}")
            st.json({"verdict": result["verdict"], "malicious": result["malicious"],
                     "suspicious": result["suspicious"], "action": result["action"],
                     "action_result": result["action_result"]})
        except Exception as exc:
            st.error(f"Could not process SIEM event: {exc}")

with tab_audit:
    st.subheader("Recent response audit trail")
    events = load_events()
    if events:
        st.dataframe(events, use_container_width=True, hide_index=True)
        st.download_button("Download audit log (JSON)", json.dumps(events, indent=2),
                           file_name="soc_audit_log.json", mime="application/json")
    else:
        st.info("No events recorded yet.")

with tab_help:
    st.subheader("Run locally")
    st.code("python -m venv .venv\n# Windows: .venv\\\\Scripts\\\\activate\n# macOS/Linux: source .venv/bin/activate\npip install -r requirements.txt\nstreamlit run app.py", language="bash")
    st.subheader("Expected SIEM event")
    st.code(json.dumps(sample, indent=2), language="json")
    st.subheader("Webhook contract")
    st.markdown("""
**Ticketing webhook:** receives a JSON object with `title`, `description`, `severity`, `source`, `alert`, and `enrichment`.

**Isolation webhook:** receives `action: isolate_vm`, `vm_id`, `reason`, `indicator`, `alert_id`, and `source`. Your EDR/SOAR adapter must translate this into the vendor-specific containment API call.

These are generic outbound webhooks, not turnkey integrations with ServiceNow, Jira, CrowdStrike, Microsoft Defender, SentinelOne, Splunk, or QRadar. Validate payloads and authentication with your vendor's API documentation before connecting production systems.
""")
    st.subheader("Security notes")
    st.markdown("""
- The app does not execute commands on endpoints directly. It sends an authenticated request to your configured response adapter.
- Automatic ticket creation and automatic isolation are disabled by default.
- Use a dedicated service account with the minimum required permissions.
- Keep API keys in environment variables or a secrets manager; do not commit secrets.
- VirusTotal detections are one signal, not proof of compromise. Tune thresholds and add analyst review to reduce false positives.
- Restrict network access to the app, enable HTTPS behind a trusted reverse proxy, and protect the audit database.
""")
