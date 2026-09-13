
from dataclasses import dataclass, field
from typing import Any

@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    user: str = "-"
    source_ip: str = "-"
    destination: str = "-"
    service: str = "-"
    status: str = "-"
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class AgentResult:
    agent: str
    status: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
