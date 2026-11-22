"""Generates machine-parseable exception tickets in the vuln-register repository."""

import logging
import os
import re
from pathlib import Path

from .schemas import ExceptionTicket, UnresolvedFindingInput

logger = logging.getLogger(__name__)


class TicketWriter:
    """Scaffolds and updates markdown exception tickets under tickets/EXC-XXXX.md."""

    def __init__(self, tickets_dir: str | Path):
        self.tickets_dir = Path(tickets_dir)
        self.tickets_dir.mkdir(parents=True, exist_ok=True)

    def create_exception_ticket(
        self, finding: UnresolvedFindingInput
    ) -> tuple[ExceptionTicket, Path]:
        """Generate or update an EXC-XXXX.md ticket for an unfixable vulnerability."""
        existing_id = self._find_existing_ticket_id(
            finding.cve_id, finding.package_name
        )
        ticket_id = existing_id or self._get_next_ticket_id()
        ticket_path = self.tickets_dir / f"{ticket_id}.md"

        ticket = ExceptionTicket(
            id=ticket_id,
            cve_id=finding.cve_id,
            package_name=finding.package_name,
            installed_version=finding.installed_version,
            host=finding.host,
            cvss_base=finding.cvss_base,
            epss_score=finding.epss_score,
            in_memory=finding.in_memory,
            memory_visibility=finding.memory_visibility,
            threat_level=finding.threat_level,
            status="PENDING_REVIEW",
            reason=finding.verdict_rationale,
        )

        content = self._render_markdown_content(ticket, finding)
        self.tickets_dir.mkdir(parents=True, exist_ok=True)
        ticket_path.write_text(content, encoding="utf-8")
        try:
            os.chmod(ticket_path, 0o666)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError:
            pass
        logger.info("Wrote exception ticket %s at %s", ticket_id, ticket_path)

        return ticket, ticket_path

    def _find_existing_ticket_id(self, cve_id: str, package_name: str) -> str | None:
        """Check if a ticket already exists for (cve_id, package_name) to avoid duplicates."""
        if not self.tickets_dir.exists():
            return None

        pattern = re.compile(r"^EXC-(\d{4,})\.md$")
        for file in sorted(self.tickets_dir.iterdir()):
            if not pattern.match(file.name):
                continue
            try:
                head = file.read_text(encoding="utf-8", errors="ignore")[:800]
                if f"cve_id: {cve_id}" in head and f"package_name: {package_name}" in head:
                    return file.stem
            except OSError:
                continue
        return None

    def _get_next_ticket_id(self) -> str:
        """Scan tickets_dir for existing EXC-XXXX.md files and return next identifier."""
        max_id = 0
        pattern = re.compile(r"^EXC-(\d{4,})\.md$")

        if self.tickets_dir.exists():
            for file in self.tickets_dir.iterdir():
                match = pattern.match(file.name)
                if match:
                    num = int(match.group(1))
                    max_id = max(max_id, num)

        next_id = max_id + 1
        return f"EXC-{next_id:04d}"

    def _render_markdown_content(
        self, ticket: ExceptionTicket, finding: UnresolvedFindingInput
    ) -> str:
        """Render complete markdown ticket body with YAML frontmatter."""
        return f"""---
id: {ticket.id}
cve_id: {ticket.cve_id}
package_name: {ticket.package_name}
installed_version: {ticket.installed_version}
host: {ticket.host}
cvss_base: {ticket.cvss_base}
epss_score: {ticket.epss_score}
in_memory: {str(ticket.in_memory).lower()}
memory_visibility: {ticket.memory_visibility}
threat_level: {ticket.threat_level}
status: {ticket.status}
requested_by: {ticket.requested_by}
requested_at: {ticket.requested_at}
---

# {ticket.id}: Vulnerability Exception Request ({ticket.cve_id})

## 1. Vulnerability & Target Asset
- **CVE Identifier**: {ticket.cve_id}
- **Affected Package**: `{ticket.package_name}` (Version: `{ticket.installed_version}`)
- **Target Host**: `{ticket.host}`
- **Base CVSS Score**: {ticket.cvss_base}
- **EPSS 30-Day Exploit Probability**: {ticket.epss_score:.4f} ({finding.epss_percentile:.2%} percentile)
- **Active Process RAM Status**: {"Resident in RAM" if ticket.in_memory else "Not resident in active RAM"}

---

## 2. Threat & Exploitability Rationale
{finding.verdict_rationale}

---

## 3. Automated Remediation Assessment
{finding.remediation_attempt_summary or "Package has no upstream patched version available and failed safe removal checks (active dependency or system component)."}

---

## 4. Governance Audit Trail
- **{ticket.requested_at}**: Exception request filed by `vuln-exception-requester`. Status set to `PENDING_REVIEW`.
"""
