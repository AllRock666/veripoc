from __future__ import annotations
from enum import Enum
from urllib.parse import urlparse
from pydantic import BaseModel, Field


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    IDOR = "idor"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


CWE_TO_CLASS = {
    89: VulnClass.SQLI, 564: VulnClass.SQLI,
    79: VulnClass.XSS, 80: VulnClass.XSS,
    918: VulnClass.SSRF,
    639: VulnClass.IDOR, 284: VulnClass.IDOR, 285: VulnClass.IDOR,
    862: VulnClass.IDOR, 863: VulnClass.IDOR,
}


class Finding(BaseModel):
    source: str                      # zap | nuclei | semgrep
    rule_id: str
    severity: str = "unknown"
    url: str
    method: str = "GET"
    param: str | None = None
    cwe: int | None = None
    vuln_class: VulnClass = VulnClass.UNKNOWN
    db_engine: str | None = None
    raw_evidence: dict = Field(default_factory=dict)

    def model_post_init(self, _):
        if self.vuln_class == VulnClass.UNKNOWN and self.cwe:
            self.vuln_class = CWE_TO_CLASS.get(self.cwe, VulnClass.UNKNOWN)
        if self.db_engine is None:
            url_lower = self.url.lower()
            parsed = urlparse(self.url)
            host = (parsed.hostname or "").lower()
            port = parsed.port
            if "dvwa" in host or port == 4280 or "dvwa" in url_lower or ":4280" in url_lower:
                self.db_engine = "mysql"
            elif "juice" in host or port == 3000 or "juice" in url_lower or ":3000" in url_lower:
                self.db_engine = "sqlite"
            else:
                self.db_engine = "sqlite"

    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        if parsed.fragment and parsed.fragment.startswith("/"):
            return f"/#{parsed.fragment.split('?')[0]}"
        return parsed.path or "/"

    @property
    def dedupe_key(self) -> tuple:
        """(endpoint, parameter, CWE) -- the unit the verifier tests once."""
        return (self.path, self.param or "", self.cwe or 0)
