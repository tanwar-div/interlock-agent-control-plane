"""Local detection patterns.

These exist as defence in depth beneath Model Armor, not as a replacement for
it. They run in-process with no network dependency, so content is still
inspected when the managed service is unreachable — which is exactly the moment
an attacker would prefer it were not.
"""
from __future__ import annotations

import re

from interlock.common.models import GuardCategory

# Attempts to override the agent's operating instructions.
INSTRUCTION_OVERRIDE = [
    r"ignore (?:all |any )?(?:your |the )?(?:previous|prior|above|earlier)\s+instructions?",
    r"disregard (?:all |any )?(?:your |the )?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?)",
    r"forget (?:everything|all)(?: you were told)?",
    r"you are (?:now|no longer) (?:a|an|in)\b",
    r"new (?:system )?(?:instructions?|directive|task)\s*[:>]",
    r"</?(?:system|instruction|admin)[^>]*>",
    r"\[\s*(?:system|admin|override)\s*\]",
    r"act as (?:a |an )?(?:root|admin|administrator|superuser)",
]

# Attempts to get the agent to bypass its own governance.
GOVERNANCE_EVASION = [
    r"(?:skip|bypass|disable|ignore|turn off)\s+(?:the\s+)?(?:approval|policy|guard|safety|review|interlock|check)",
    r"(?:do not|don'?t)\s+(?:log|record|audit|report|escalate)",
    r"without (?:asking|approval|confirmation|human|review)",
    r"this is (?:pre[- ]?)?(?:approved|authorised|authorized)",
    r"emergency override",
    r"maintenance mode",
]

# Attempts to widen access.
PRIVILEGE_ESCALATION = [
    r"\ballUsers\b",
    r"\ballAuthenticatedUsers\b",
    r"roles/(?:owner|editor)\b",
    r"make (?:it |the .{0,24})?public",
    r"grant (?:me |them |everyone )?(?:full |admin |owner )?access",
    r"0\.0\.0\.0/0",
    r"chmod\s+777",
]

# Credential-shaped strings that must never leave the system.
SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"ya29\.[0-9A-Za-z_\-]+", "Google OAuth token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "private key block"),
    (r"sk-[A-Za-z0-9]{20,}", "API secret key"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r'"type"\s*:\s*"service_account"', "service account JSON"),
    (r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "inline credential"),
]

# Personal data shapes.
PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "US social security number"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "payment card number"),
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "email address"),
    (r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b", "phone number"),
]

_FLAGS = re.IGNORECASE | re.MULTILINE

COMPILED: list[tuple[GuardCategory, re.Pattern[str], str]] = []
for _p in INSTRUCTION_OVERRIDE:
    COMPILED.append((GuardCategory.PROMPT_INJECTION, re.compile(_p, _FLAGS), "instruction override"))
for _p in GOVERNANCE_EVASION:
    COMPILED.append((GuardCategory.JAILBREAK, re.compile(_p, _FLAGS), "governance evasion"))
for _p in PRIVILEGE_ESCALATION:
    COMPILED.append((GuardCategory.PROMPT_INJECTION, re.compile(_p, _FLAGS), "privilege escalation"))
for _p, _label in SECRET_PATTERNS:
    COMPILED.append((GuardCategory.SECRET, re.compile(_p, _FLAGS), _label))
for _p, _label in PII_PATTERNS:
    COMPILED.append((GuardCategory.PII, re.compile(_p, _FLAGS), _label))


def scan(text: str) -> list[tuple[GuardCategory, str, str]]:
    """Return (category, label, matched_excerpt) for every hit."""
    findings: list[tuple[GuardCategory, str, str]] = []
    if not text:
        return findings
    for category, pattern, label in COMPILED:
        match = pattern.search(text)
        if match:
            excerpt = match.group(0)
            if len(excerpt) > 60:
                excerpt = excerpt[:57] + "..."
            findings.append((category, label, excerpt))
    return findings
