# SOC Alert Enrichment & Response

A Streamlit SOC/SOAR starter app that accepts an IP address or file hash, queries VirusTotal, evaluates malicious detections, optionally opens a ticket through a generic webhook, and can send a VM-isolation request to an EDR/SOAR adapter.

## Run

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL Streamlit prints (normally http://localhost:8501).

## Configure

Set `VT_API_KEY` in your environment, or paste the key into the app sidebar. Optional webhook settings can also be supplied as environment variables; see `.env.example`.

## SIEM event format

```json
{
  "alert_id": "ALERT-2026-0001",
  "indicator": "8.8.8.8",
  "vm_id": "lab-vm-01",
  "source": "Example SIEM",
  "severity": "high"
}
```

The Streamlit intake accepts this JSON manually. For production SIEM push ingestion, expose a separately authenticated API endpoint (for example, FastAPI) or have your SOAR platform call an adapter that validates and forwards events to the enrichment function. Do not expose the Streamlit UI directly as an unauthenticated webhook receiver.

## Response webhook integration

- Ticket webhook: receives `title`, `description`, `severity`, `source`, `alert`, and `enrichment`.
- Isolation webhook: receives `action`, `vm_id`, `reason`, `indicator`, `alert_id`, and `source`.

The isolation webhook is an integration boundary. Implement it in a trusted EDR/SOAR environment using that vendor's official API, authentication, and target validation. The app does not directly isolate machines.

## Safety defaults

- Automatic ticketing is off by default.
- Automatic isolation is off by default and requires explicit configuration in the UI.
- Manual isolation requires an analyst confirmation checkbox.
- VirusTotal scores are triage signals; validate before containment.
- Use a lab VM and test webhook receiver before production use.
- Protect the app with authentication, TLS, network restrictions, and secrets management before deployment.
