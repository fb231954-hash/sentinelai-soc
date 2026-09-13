
import streamlit as st, json
from datetime import datetime, timezone
from pathlib import Path
from sentinelai.database import init_db, audit, save_events, save_incident, update_incident, incidents, audit_rows, event_count
from sentinelai.agents import SOCOrchestrator, VerificationAgent

init_db()
st.set_page_config(page_title="SentinelAI | AI SOC", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp{background:radial-gradient(circle at 15% 0%,#183856 0,#07111f 38%,#040a12 100%);color:#eaf3fa}
.block-container{max-width:1500px;padding:1.1rem 2rem 3rem}
.hero{background:linear-gradient(135deg,#122a43,#0a1624 80%);border:1px solid #2a4f6c;border-radius:24px;padding:28px 34px;margin-bottom:18px;box-shadow:0 20px 70px #0006}
.hero h1{font-size:48px;line-height:1;margin:0}.hero p{font-size:16px;color:#a9c9e5;margin:.65rem 0 0}
.card{background:linear-gradient(180deg,#0d1d2d,#0a1826);border:1px solid #203b53;border-radius:16px;padding:17px;min-height:108px}
.kpi{font-size:32px;font-weight:800;margin-top:5px}.label{font-size:11px;letter-spacing:1.1px;color:#7fa1b8;text-transform:uppercase}
.agent{background:#091827;border:1px solid #23455f;border-left:4px solid #4aa8ff;border-radius:12px;padding:13px 16px;margin:7px 0}
.pill{display:inline-block;padding:4px 10px;border-radius:999px;background:#102b42;border:1px solid #2c5778;font-size:11px}
.critical{color:#ff8f9a;background:#4c1821}.high{color:#ffd18b;background:#493418}.medium{color:#f1df8d;background:#473e18}
.safe{background:#092b24;border:1px solid #2d806c;border-radius:12px;padding:14px}.warn{background:#2a2212;border:1px solid #8f702c;border-radius:12px;padding:14px}
.flow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:7px 0 16px}.node{background:#0d2438;border:1px solid #2a5574;border-radius:9px;padding:7px 10px;font-size:11px}.arrow{color:#66b8ef}
</style>
""", unsafe_allow_html=True)

for k,v in {"raw":"","res":None,"iid":None,"approved":False,"acted":False,"verified":False}.items():
    if k not in st.session_state: st.session_state[k]=v

def demo_bruteforce(n=60):
    return "\n".join(f"2026-09-03T10:{i//60:02d}:{i%60:02d}Z FAILED_LOGIN user=admin src=185.77.21.44 service=ssh" for i in range(n))
def demo_scan(n=12):
    return "\n".join(f"2026-09-03T11:{i:02d}:00Z PORT_SCAN src=203.0.113.55 dst=10.10.0.20 ports={20+i}" for i in range(n))
def demo_mixed():
    return demo_bruteforce(40)+"\n"+demo_scan(8)
def create_incident(r):
    d,rr,m,inv=r["detection"],r["risk"],r["mitre"],r["investigation"]
    iid="INC-"+datetime.now().strftime("%Y%m%d-%H%M%S")
    summary=f"SentinelAI correlated {d['count']} events consistent with {d['type'].lower()} from {d['source_ip']}. Risk {rr['risk']}/100 with {rr['confidence']}% confidence."
    row=(iid,datetime.now(timezone.utc).isoformat(),d["type"],rr["severity"],rr["risk"],rr["confidence"],d["source_ip"],d["target"],
         m["id"],m["name"],m["tactic"],"AWAITING_HUMAN_APPROVAL",summary,json.dumps(inv["evidence"]),r["response"]["recommendation"],0,0,0)
    save_incident(row); audit("INCIDENT_CREATED",iid); return iid

st.sidebar.markdown("## 🛡️ SentinelAI")
st.sidebar.caption("AI-Powered Autonomous Security Operations Center")
page=st.sidebar.radio("Control Center",["Executive Dashboard","Customer Demo","Live Detection","Agent Command Center","Investigation","Response Center","Incident Reports","Architecture & Product"])
st.sidebar.divider()
st.sidebar.success("● SOC ONLINE")
st.sidebar.caption("v4.0 • Multi-Agent Orchestration")
st.sidebar.caption("Human approval • Audit memory • Defensive mode")
st.sidebar.divider()
st.sidebar.caption("Built for academic demonstration + future productization")

st.markdown("""<div class="hero"><h1>🛡️ SentinelAI</h1>
<p>Autonomous AI Security Operations Center — Detect • Investigate • Assess • Respond • Verify</p>
</div>""",unsafe_allow_html=True)

if page=="Executive Dashboard":
    rows=incidents()
    c=st.columns(5)
    vals=[len(st.session_state.res["events"]) if st.session_state.res and st.session_state.res.get("detected") else 0,
          len(rows),sum(x["severity"]=="CRITICAL" for x in rows),len(audit_rows()),rows[0]["risk"] if rows else "—"]
    for col,label,val in zip(c,["Events in Current Run","Incidents","Critical","Audit Records","Current Risk"] ,vals):
        col.markdown(f'<div class="card"><div class="label">{label}</div><div class="kpi">{val}</div></div>',unsafe_allow_html=True)
    st.subheader("SOC Mission Control")
    st.markdown("""<div class="flow"><span class="node">INGEST</span><span class="arrow">→</span><span class="node">NORMALIZE</span><span class="arrow">→</span><span class="node">DETECT</span><span class="arrow">→</span><span class="node">ENRICH</span><span class="arrow">→</span><span class="node">INVESTIGATE</span><span class="arrow">→</span><span class="node">RISK</span><span class="arrow">→</span><span class="node">MITRE</span><span class="arrow">→</span><span class="node">APPROVE</span><span class="arrow">→</span><span class="node">ACT</span><span class="arrow">→</span><span class="node">VERIFY</span></div>""",unsafe_allow_html=True)
    l,r=st.columns([2,1])
    with l:
        st.markdown("### Command Center")
        st.write("One workspace for security visibility, autonomous investigation and controlled response.")
        st.write("**Designed for:** SMBs • Universities • MSSPs • IT/Security Teams • SaaS/Cloud Teams")
    with r:
        if st.button("🚨 Launch Flagship Demo",type="primary",use_container_width=True):
            st.session_state.raw=demo_bruteforce(); st.session_state.res=None
            st.session_state.approved=st.session_state.acted=st.session_state.verified=False
            audit("DEMO_LOADED","60 synthetic SSH failed-login events"); st.rerun()

elif page=="Customer Demo":
    st.subheader("✨ Customer Demo — See the value in 60 seconds")
    st.caption("This view is intentionally outcome-focused: customers see the security problem, the decision and the business value.")
    cols=st.columns(3)
    with cols[0]:
        st.markdown('<div class="card"><div class="label">BEFORE</div><div class="kpi">60</div><p>Raw security events requiring review</p></div>',unsafe_allow_html=True)
    with cols[1]:
        st.markdown('<div class="card"><div class="label">AFTER</div><div class="kpi">1</div><p>Correlated, prioritized incident</p></div>',unsafe_allow_html=True)
    with cols[2]:
        st.markdown('<div class="card"><div class="label">DECISION</div><div class="kpi">96</div><p>Illustrative risk score / 100</p></div>',unsafe_allow_html=True)
    st.markdown("### One-click product demonstration")
    a,b,c=st.columns(3)
    if a.button("1. Generate Attack Telemetry",use_container_width=True):
        st.session_state.raw=demo_bruteforce(); audit("CUSTOMER_DEMO","Flagship telemetry generated"); st.success("Telemetry generated: 60 synthetic events.")
    if b.button("2. Ask SentinelAI to Investigate",use_container_width=True):
        st.session_state.res=SOCOrchestrator().run(st.session_state.raw or demo_bruteforce())
        if st.session_state.res["detected"]:
            save_events(st.session_state.res["events"]); st.session_state.iid=create_incident(st.session_state.res)
        audit("CUSTOMER_DEMO_ANALYSIS","Autonomous investigation completed"); st.rerun()
    if c.button("3. Show Verified Outcome",use_container_width=True):
        if st.session_state.res and st.session_state.res.get("detected"):
            st.session_state.approved=st.session_state.acted=st.session_state.verified=True
            update_incident(st.session_state.iid,status="VERIFIED",approved=1,action_executed=1,verified=1)
            audit("CUSTOMER_DEMO_VERIFIED",st.session_state.iid); st.rerun()
        else: st.warning("Run the investigation first.")
    if st.session_state.res and st.session_state.res.get("detected"):
        r=st.session_state.res
        st.markdown(f"### 🚨 {r['detection']['type']} — {r['risk']['severity']}")
        st.write(f"**Source:** `{r['detection']['source_ip']}` • **MITRE:** `{r['mitre']['id']}` • **Risk:** `{r['risk']['risk']}/100`")
        st.write("**AI conclusion:** Repeated authentication failures were correlated as a likely automated credential-guessing pattern. SentinelAI enriched the source, investigated the evidence, mapped the behavior and prepared a controlled containment decision.")
        st.markdown('<div class="safe"><b>Business value:</b> reduce repetitive triage, shorten time-to-investigate, standardize analyst decisions and keep consequential actions under authorization.</div>',unsafe_allow_html=True)

elif page=="Live Detection":
    st.subheader("📡 Live Security Event Ingestion")
    up=st.file_uploader("Upload authorized server / network / authentication / firewall log",type=["log","txt"])
    if up:
        st.session_state.raw=up.read().decode("utf-8","ignore"); audit("LOG_UPLOADED",up.name)
        st.success(f"Loaded {up.name}")
    st.session_state.raw=st.text_area("Security event stream",value=st.session_state.raw or demo_bruteforce(20),height=270)
    a,b,c=st.columns(3)
    if a.button("Load Brute-Force Scenario",use_container_width=True):
        st.session_state.raw=demo_bruteforce(); audit("DEMO_LOADED","60 synthetic brute-force events"); st.success("✓ 60 events loaded"); st.rerun()
    if b.button("Load Port-Scan Scenario",use_container_width=True):
        st.session_state.raw=demo_scan(); audit("DEMO_LOADED","12 synthetic port-scan events"); st.success("✓ 12 scan events loaded"); st.rerun()
    if c.button("🤖 Run Autonomous Analysis",type="primary",use_container_width=True):
        st.session_state.res=SOCOrchestrator().run(st.session_state.raw); st.session_state.approved=st.session_state.acted=st.session_state.verified=False
        if st.session_state.res.get("detected"):
            save_events(st.session_state.res["events"]); st.session_state.iid=create_incident(st.session_state.res); audit("SOC_ANALYSIS_COMPLETE",st.session_state.iid)
        else: audit("SOC_ANALYSIS_COMPLETE","No high-confidence threat")
        st.rerun()
    if st.session_state.res:
        st.success("🚨 THREAT DETECTED — investigation package created." if st.session_state.res.get("detected") else "No high-confidence threat detected.")

elif page=="Agent Command Center":
    st.subheader("🤖 Agent Command Center")
    st.caption("Transparent multi-agent execution — each specialist returns a structured result to the orchestrator.")
    r=st.session_state.res
    if not r: st.info("Launch the flagship demo first.")
    else:
        for i,a in enumerate(r["agents"],1):
            st.markdown(f'<div class="agent"><b>{i:02d}. {a.agent}</b> <span style="float:right" class="pill">{a.status}</span><br><span style="color:#9cb1c2">{a.summary}</span></div>',unsafe_allow_html=True)
        st.markdown("### Decision loop")
        st.write("**OBSERVE → REASON → PLAN → HUMAN APPROVAL → ACT → VERIFY**")
        st.write("The orchestrator creates a task plan and passes structured evidence between specialist agents. This makes the workflow explainable rather than a single chat response.")

elif page=="Investigation":
    st.subheader("🔎 Investigation Workbench")
    r=st.session_state.res
    if not r or not r.get("detected"): st.info("No active threat. Run a demo.")
    else:
        d,rr,ti,iv,m=r["detection"],r["risk"],r["intel"],r["investigation"],r["mitre"]
        c=st.columns(5)
        c[0].metric("Risk",f'{rr["risk"]}/100'); c[1].metric("Confidence",f'{rr["confidence"]}%'); c[2].metric("Events",d["count"]); c[3].metric("MITRE",m["id"]); c[4].metric("Priority",d["priority"])
        st.markdown(f"### {d['type']} • **{rr['severity']}**")
        x,y=st.columns(2)
        with x:
            st.markdown("#### Evidence Chain")
            for e in iv["evidence"]: st.write("• "+e)
            st.markdown("#### Threat Intelligence")
            st.write(f"**Reputation:** {ti['reputation']}")
            st.write(f"**Confidence:** {ti['confidence']}%")
            st.caption("Academic offline feed; production connector ready.")
        with y:
            st.markdown("#### MITRE ATT&CK")
            st.info(f'{m["id"]} — {m["name"]}\n\nTactic: {m["tactic"]}\n\n{m["reason"]}')
            st.markdown("#### Incident Timeline")
            for e in iv["timeline"][:12]:
                st.write(f'`{e.timestamp}` — {e.event_type} — `{e.source_ip}` — `{e.user}`')
        st.markdown("#### Analyst-Ready Summary")
        st.write(f"SentinelAI correlated repeated activity from `{d['source_ip']}` and assessed the incident as **{rr['severity']}** with **{rr['risk']}/100** risk. The decision is supported by event frequency, IOC context and behavior pattern.")

elif page=="Response Center":
    st.subheader("🛡️ Human-in-the-Loop Response Center")
    r=st.session_state.res
    if not r or not r.get("detected"): st.info("No active incident.")
    else:
        st.markdown(f'<div class="warn"><b>Recommended response</b><br>{r["response"]["recommendation"]}<br><br><b>Approval policy:</b> consequential response requires an authorized human.<br><b>Safety:</b> {r["response"]["safety"]}</div>',unsafe_allow_html=True)
        st.write(f"Incident: `{st.session_state.iid}` • Approval: **{'APPROVED' if st.session_state.approved else 'PENDING'}**")
        a,b=st.columns(2)
        if a.button("✅ Approve Controlled Response",use_container_width=True):
            st.session_state.approved=True; update_incident(st.session_state.iid,status="APPROVED",approved=1); audit("HUMAN_APPROVED",st.session_state.iid); st.rerun()
        if b.button("⛔ Reject Response",use_container_width=True):
            update_incident(st.session_state.iid,status="REJECTED"); audit("HUMAN_REJECTED",st.session_state.iid); st.error("Response rejected. No action executed.")
        if st.session_state.approved:
            if st.button("⚡ Execute Controlled Containment",type="primary",use_container_width=True):
                st.session_state.acted=True; update_incident(st.session_state.iid,status="ACTION_EXECUTED",action_executed=1); audit("CONTROLLED_CONTAINMENT","Simulation only"); st.rerun()
        if st.session_state.acted:
            st.success("Controlled containment completed in simulation — no live infrastructure modified.")
            if st.button("🔍 Verify Response",use_container_width=True):
                VerificationAgent().run(); st.session_state.verified=True; update_incident(st.session_state.iid,status="VERIFIED",verified=1); audit("VERIFICATION_COMPLETE",st.session_state.iid); st.rerun()
        if st.session_state.verified: st.markdown('<div class="safe"><b>✓ VERIFIED</b><br>Response result validated and written to audit memory.</div>',unsafe_allow_html=True)

elif page=="Incident Reports":
    st.subheader("📋 Incident Reports & Audit Memory")
    rows=incidents()
    if not rows: st.info("No incidents yet.")
    for r in rows[:15]:
        with st.expander(f'{r["incident_id"]} • {r["severity"]} • Risk {r["risk"]}/100 • {r["status"]}'):
            st.write(r["summary"])
            st.write(f'Source: `{r["source_ip"]}` • Target: `{r["target"]}` • MITRE: `{r["mitre_id"]} — {r["mitre_name"]}`')
            rep=f"""SENTINELAI INCIDENT REPORT
Incident ID: {r["incident_id"]}
Created: {r["created_at"]}
Type: {r["incident_type"]}
Severity: {r["severity"]}
Risk: {r["risk"]}/100
Confidence: {r["confidence"]}%
Source IP: {r["source_ip"]}
Target: {r["target"]}
MITRE: {r["mitre_id"]} — {r["mitre_name"]}
Tactic: {r["tactic"]}
Status: {r["status"]}
Approved: {bool(r["approved"])}
Action Executed: {bool(r["action_executed"])}
Verified: {bool(r["verified"])}

SUMMARY
{r["summary"]}

EVIDENCE
{r["evidence"]}

RECOMMENDED ACTION
{r["recommended_action"]}

SentinelAI — Defensive academic prototype."""
            st.download_button("Download incident report",rep,file_name=f'{r["incident_id"]}.txt')
    st.markdown("### Audit Trail")
    for a in audit_rows(): st.write(f'`{a["ts"]}` **{a["action"]}** — {a["detail"]}')

else:
    st.subheader("🏗️ Architecture & Product")
    st.code("""AUTHORIZED SECURITY SOURCES
(server • network • authentication • firewall • SIEM)
                      ↓
            INGESTION / NORMALIZATION
                      ↓
            SOC ORCHESTRATOR / PLANNER
                      ↓
    ┌─────────────────┼─────────────────┐
    ↓                 ↓                 ↓
LOG ANALYSIS     THREAT DETECTION   THREAT INTEL
    ↓                 ↓                 ↓
    └──────────── INVESTIGATION ────────┘
                      ↓
              RISK ASSESSMENT
                      ↓
                MITRE ATT&CK
                      ↓
             INCIDENT RESPONSE
                      ↓
               HUMAN APPROVAL
                      ↓
              CONTROLLED ACTION
                      ↓
                VERIFICATION
                      ↓
              AUDIT MEMORY / REPORT""")
    st.markdown("### Product target audience")
    cols=st.columns(4)
    for col,t,b in zip(cols,["SMBs","Universities","MSSPs","IT / SaaS Teams"],
                       ["Reduce repetitive SOC triage without a large 24/7 team.",
                        "Protect campus infrastructure with a centralized security workflow.",
                        "Offer repeatable investigation workflows across customer environments.",
                        "Add an AI security operations layer to internal systems."]):
        col.markdown(f'<div class="card"><div class="label">{t}</div><p>{b}</p></div>',unsafe_allow_html=True)
    st.markdown("### Product tiers")
    st.write("**Starter:** local logs + investigation • **Pro:** SIEM/TI connectors + alerts • **Enterprise:** RBAC/SSO, multi-tenancy, immutable audit, cloud deployment and security-tested response playbooks.")
    st.markdown("### Important product boundary")
    st.write("This academic build is safe by design. It does not exploit, scan or modify real infrastructure. A commercial release requires authorized connectors, secure secrets management, access controls, privacy controls and professional security testing.")
