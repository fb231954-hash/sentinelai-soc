# SentinelAI Viva Cheat Sheet

**Q: Is it just a chatbot?**
A: No. It maintains state, decomposes a security task across specialist agents, stores incident/audit state, requires human approval for consequential response, and verifies the result.

**Q: What makes it autonomous?**
A: The SOC Orchestrator chooses and executes a multi-step investigation pipeline based on structured results from specialist agents.

**Q: Why human approval?**
A: Blocking or containment can be consequential. The prototype deliberately gates that action to demonstrate safe AI operations.

**Q: What is the flagship attack?**
A: Synthetic SSH brute-force behavior: 60 failed logins from one source IP targeting an admin account.

**Q: Why MITRE ATT&CK?**
A: It gives analysts a standardized language for adversary behavior; the demo maps brute force to T1110.

**Q: Can it become a real product?**
A: Yes as an engineering foundation. Production requires authenticated SIEM/TI connectors, RBAC/SSO, secure secret storage, cloud persistence, monitoring and professional security testing.

**Q: What was learned?**
A: Multi-agent orchestration, defensive detection, investigation, risk scoring, explainability, human-in-the-loop controls, auditability and product design.
