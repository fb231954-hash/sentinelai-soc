
import re
from .models import SecurityEvent

FAILED = re.compile(
    r"(?P<ts>\S+)\s+FAILED_LOGIN\s+user=(?P<user>\S+)\s+src=(?P<ip>\S+)\s+service=(?P<svc>\S+)",
    re.I,
)
SUCCESS = re.compile(
    r"(?P<ts>\S+)\s+SUCCESS_LOGIN\s+user=(?P<user>\S+)\s+src=(?P<ip>\S+)\s+service=(?P<svc>\S+)",
    re.I,
)
SCAN = re.compile(
    r"(?P<ts>\S+)\s+PORT_SCAN\s+src=(?P<ip>\S+)\s+dst=(?P<dst>\S+)\s+ports=(?P<ports>\d+)",
    re.I,
)
FIREWALL = re.compile(
    r"(?P<ts>\S+)\s+FIREWALL_BLOCK\s+src=(?P<ip>\S+)\s+dst=(?P<dst>\S+)\s+proto=(?P<proto>\S+)\s+reason=(?P<reason>.+)",
    re.I,
)

def parse_logs(raw: str) -> list[SecurityEvent]:
    events=[]
    for line in raw.splitlines():
        line=line.strip()
        if not line:
            continue
        m=FAILED.search(line)
        if m:
            g=m.groupdict()
            events.append(SecurityEvent(g["ts"], "FAILED_LOGIN", g["user"], g["ip"], service=g["svc"], status="failed", raw=line))
            continue
        m=SUCCESS.search(line)
        if m:
            g=m.groupdict()
            events.append(SecurityEvent(g["ts"], "SUCCESS_LOGIN", g["user"], g["ip"], service=g["svc"], status="success", raw=line))
            continue
        m=SCAN.search(line)
        if m:
            g=m.groupdict()
            events.append(SecurityEvent(g["ts"], "PORT_SCAN", source_ip=g["ip"], destination=g["dst"],
                                        metadata={"ports": int(g["ports"])}, raw=line))
            continue
        m=FIREWALL.search(line)
        if m:
            g=m.groupdict()
            events.append(SecurityEvent(g["ts"], "FIREWALL_BLOCK", source_ip=g["ip"], destination=g["dst"],
                                        status="blocked", metadata={"protocol":g["proto"],"reason":g["reason"]}, raw=line))
    return events
