from typing import Literal

IntrusionStage = Literal[
    "collection",
    "command-and-control",
    "credential-access",
    "defense-impairment",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "reconnaissance",
    "resource-development",
    "stealth",
]
