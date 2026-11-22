"""Data contracts and schemas for vulnerability exception requests."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator


class UnresolvedFindingInput(BaseModel):
    """Payload received from vuln-patch-analyst containing unfixable CVE details."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    package_name: str = Field(..., min_length=1)
    installed_version: str = Field(..., min_length=1)
    host: str = Field(default="lejeune")
    cvss_base: float = Field(..., ge=0.0, le=10.0)
    epss_score: float = Field(..., ge=0.0, le=1.0)
    epss_percentile: float = Field(..., ge=0.0, le=1.0)
    in_memory: bool
    memory_visibility: str = "partial"
    threat_level: str
    verdict_rationale: str
    remediation_attempt_summary: str = ""

    @field_validator("cve_id", mode="before")
    def force_uppercase_cve(cls, v: str) -> str:
        """Ensure uppercase CVE formatting."""
        if isinstance(v, str):
            return v.strip().upper()
        return v


class ExceptionTicket(BaseModel):
    """Frontmatter metadata for an exception ticket."""

    id: str = Field(..., pattern=r"^EXC-\d{4,}$")
    cve_id: str
    package_name: str
    installed_version: str
    host: str
    cvss_base: float
    epss_score: float
    in_memory: bool
    memory_visibility: str = "partial"
    threat_level: str
    status: str = Field(default="PENDING_REVIEW")
    requested_by: str = Field(default="vuln-exception-requester")
    requested_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    reason: str


class RegisterEntry(BaseModel):
    """Record representing a vulnerability entry in the master register."""

    cve_id: str
    package_name: str
    installed_version: str
    host: str
    cvss_base: float
    epss_score: float
    in_memory: bool
    status: str = "PENDING_REVIEW"
    expiration: str = "PENDING_APPROVAL"
    ticket_ref: str
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
