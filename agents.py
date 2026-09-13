
from collections import Counter
from .models import AgentResult
from .parsers import parse_logs

class LogAnalysisAgent:
    name="Log Analysis Agent"
    def run(self, raw):
        events=parse_logs(raw)
        types=Counter(e.event_type for e in events)
        return AgentResult(
            self.name,"COMPLETED",
            f"Normalized {len(events)} events across {len(types)} event types.",
            {"events":events,"count":len(events),"types":dict(types)}
        )

class ThreatDetectionAgent:
    name="Threat Detection Agent"
    def run(self, events):
        failed=[e for e in events if e.event_type=="FAILED_LOGIN"]
        scans=[e for e in events if e.event_type=="PORT_SCAN"]
        blocks=[e for e in events if e.event_type=="FIREWALL_BLOCK"]

        if failed:
            ip,n=Counter(e.source_ip for e in failed).most_common(1)[0]
            if n>=8:
                return AgentResult(
                    self.name,"THREAT",
                    f"Detected SSH brute-force behavior: {n} failed logins from {ip}.",
                    {"detected":True,"type":"SSH Brute-Force Attack","source_ip":ip,"count":n,
                     "target":failed[0].service or "SSH","user":failed[0].user,"priority":"P1"}
                )
        if scans:
            ip,n=Counter(e.source_ip for e in scans).most_common(1)[0]
            if n>=5:
                return AgentResult(
                    self.name,"THREAT",
                    f"Detected network scanning behavior: {n} scan events from {ip}.",
                    {"detected":True,"type":"Network Port Scan","source_ip":ip,"count":n,
                     "target":scans[0].destination or "Internal host","user":"-","priority":"P2"}
                )
        if blocks:
            ip,n=Counter(e.source_ip for e in blocks).most_common(1)[0]
            if n>=3:
                return AgentResult(
                    self.name,"THREAT",
                    f"Detected repeated blocked firewall traffic from {ip}.",
                    {"detected":True,"type":"Repeated Malicious Traffic","source_ip":ip,"count":n,
                     "target":blocks[0].destination or "Protected asset","user":"-","priority":"P2"}
                )
        return AgentResult(self.name,"CLEAR","No high-confidence threat pattern detected.",{"detected":False})

class ThreatIntelligenceAgent:
    name="Threat Intelligence Agent"
    DEMO={
        "185.77.21.44":("Malicious / demo IOC",95),
        "203.0.113.55":("Suspicious / documentation IOC",82),
        "198.51.100.10":("Known suspicious demo IOC",79),
    }
    def run(self,detection):
        ip=detection.get("source_ip","-")
        rep,conf=self.DEMO.get(ip,("Unknown — external TI connector ready",38))
        return AgentResult(self.name,"ENRICHED",
                           f"{ip}: {rep} ({conf}% confidence).",
                           {"ip":ip,"reputation":rep,"confidence":conf,
                            "sources":["Offline academic TI feed"],"ioc_type":"IPv4"})

class InvestigationAgent:
    name="Investigation Agent"
    def run(self,events,detection,intel):
        ip=detection["source_ip"]
        related=[e for e in events if e.source_ip==ip]
        users=sorted({e.user for e in related if e.user!="- " and e.user!="-"})
        services=sorted({e.service for e in related if e.service!="-"})
        evidence=[
            f"{detection.get('count',len(related))} related security events correlated",
            f"Source IP: {ip}",
            f"Target account(s): {', '.join(users) if users else '-'}",
            f"Service/asset: {', '.join(services) if services else detection.get('target','-')}",
            f"IOC reputation: {intel['reputation']}",
        ]
        return AgentResult(self.name,"COMPLETED",
                           f"Correlated {len(related)} related events into one investigation.",
                           {"evidence":evidence,"timeline":related[:24],"related_count":len(related)})

class RiskAssessmentAgent:
    name="Risk Assessment Agent"
    def run(self,detection,intel,investigation):
        n=detection.get("count",0)
        risk=min(99,55 + min(30,n//2) + (10 if intel["confidence"]>=80 else 0))
        if detection["type"]=="Network Port Scan":
            risk=max(35,risk-10)
        severity="CRITICAL" if risk>=90 else "HIGH" if risk>=75 else "MEDIUM" if risk>=50 else "LOW"
        confidence=min(99,83+n//5)
        return AgentResult(self.name,"SCORED",f"Risk {risk}/100 — {severity}.",
                           {"risk":risk,"severity":severity,"confidence":confidence,
                            "factors":["event frequency","IOC context","target exposure","behavior pattern"]})

class MitreMappingAgent:
    name="MITRE ATT&CK Mapping Agent"
    def run(self,detection):
        if detection["type"]=="SSH Brute-Force Attack":
            x={"id":"T1110","name":"Brute Force","tactic":"Credential Access","reason":"Repeated authentication failures indicate credential-guessing behavior."}
        elif detection["type"]=="Network Port Scan":
            x={"id":"T1046","name":"Network Service Scanning","tactic":"Discovery","reason":"Repeated probing of network services indicates discovery activity."}
        else:
            x={"id":"T1071.001","name":"Web Protocols","tactic":"Command and Control","reason":"Repeated blocked traffic is treated as suspicious communication in the demo model."}
        return AgentResult(self.name,"MAPPED",f"{x['id']} — {x['name']}.",x)

class IncidentResponseAgent:
    name="Incident Response Agent"
    def run(self,detection,risk):
        ip=detection["source_ip"]
        action=f"Contain source IP {ip} at the authorized security boundary, preserve evidence and increase monitoring."
        return AgentResult(self.name,"READY",action,
                           {"recommendation":action,"requires_approval":True,
                            "mode":"SIMULATED_CONTAINMENT",
                            "safety":"Academic prototype: no real firewall/server/endpoint is modified."})

class VerificationAgent:
    name="Verification Agent"
    def run(self,action="SIMULATED_CONTAINMENT"):
        return AgentResult(self.name,"VERIFIED",
                           f"Verified {action}: expected controlled state recorded in the audit trail.",
                           {"verified":True,"checks":["action-state recorded","incident state updated","audit entry created"]})

class SOCOrchestrator:
    def run(self,raw):
        chain=[]
        a=LogAnalysisAgent().run(raw); chain.append(a)
        d=ThreatDetectionAgent().run(a.data["events"]); chain.append(d)
        if not d.data.get("detected"):
            return {"detected":False,"agents":chain}
        ti=ThreatIntelligenceAgent().run(d.data); chain.append(ti)
        inv=InvestigationAgent().run(a.data["events"],d.data,ti.data); chain.append(inv)
        risk=RiskAssessmentAgent().run(d.data,ti.data,inv.data); chain.append(risk)
        mitre=MitreMappingAgent().run(d.data); chain.append(mitre)
        resp=IncidentResponseAgent().run(d.data,risk.data); chain.append(resp)
        return {"detected":True,"agents":chain,"events":a.data["events"],"detection":d.data,
                "intel":ti.data,"investigation":inv.data,"risk":risk.data,
                "mitre":mitre.data,"response":resp.data}
