# SentinelAI — Autonomous AI Security Operations Center v4.0

## Academic Final + Product Foundation

SentinelAI is a defensive multi-agent SOC prototype designed around:

**OBSERVE → REASON → PLAN → HUMAN APPROVAL → ACT → VERIFY**

### Specialist agents
- SOC Orchestrator / Planner
- Log Analysis Agent
- Threat Detection Agent
- Threat Intelligence Agent
- Investigation Agent
- Risk Assessment Agent
- MITRE ATT&CK Mapping Agent
- Incident Response Agent
- Human Approval Layer
- Verification Agent

### Covered inputs
Server logs, network logs, authentication logs and firewall alerts (synthetic/authorized demo data).

### Detection scenarios
- SSH brute-force
- Network port scanning
- Repeated suspicious firewall traffic

### Product features
- Professional SOC command center
- Customer demo mode
- Log upload
- Risk + confidence scoring
- Evidence chain and timeline
- MITRE ATT&CK mapping
- Human approval workflow
- Controlled response simulation
- Verification
- SQLite incident/audit memory
- Incident report export
- Deployment configuration
- Product positioning / roadmap

## Run in VS Code — Windows

Recommended:
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If your machine has Python 3.14 and you encounter dependency problems, Python 3.12 is the safest academic environment.

## Teacher demo
1. Executive Dashboard
2. Launch Flagship Demo
3. Live Detection → Run Autonomous Analysis
4. Agent Command Center
5. Investigation
6. Response Center
7. Approve Controlled Response
8. Execute Controlled Containment
9. Verify Response
10. Incident Reports
11. Architecture & Product

## Customer demo
Open **Customer Demo** and click:
Generate Attack Telemetry → Ask SentinelAI to Investigate → Show Verified Outcome.

## Safety
This project uses synthetic/authorized data. It does not attack, scan or modify real systems. Response execution is intentionally simulated and human-gated.

## Commercial roadmap
For a production SaaS, add authenticated SIEM connectors (e.g. Wazuh/Elastic/Splunk), real threat-intelligence APIs, RBAC/SSO, tenant isolation, secure secret storage, alerting, cloud persistence, compliance reporting and security testing.
