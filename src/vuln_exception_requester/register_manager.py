"""Maintains the living vulnerability register in JSON and Markdown formats."""

import json
import logging
from pathlib import Path

from .schemas import ExceptionTicket, RegisterEntry

logger = logging.getLogger(__name__)


class RegisterManager:
    """Manages reading and updating register/vulnerability_register.json and .md."""

    def __init__(self, register_dir: str | Path):
        self.register_dir = Path(register_dir)
        self.json_path = self.register_dir / "vulnerability_register.json"
        self.md_path = self.register_dir / "vulnerability_register.md"
        self.register_dir.mkdir(parents=True, exist_ok=True)

    def record_pending_exceptions_batch(
        self, tickets: list[ExceptionTicket]
    ) -> list[RegisterEntry]:
        """Add or update multiple entries in the register in a single atomic write."""
        if not tickets:
            return []

        data = self._load_json_register()
        vulnerabilities = data.get("vulnerabilities", [])
        created_entries: list[RegisterEntry] = []

        for ticket in tickets:
            entry = RegisterEntry(
                cve_id=ticket.cve_id,
                package_name=ticket.package_name,
                installed_version=ticket.installed_version,
                host=ticket.host,
                cvss_base=ticket.cvss_base,
                epss_score=ticket.epss_score,
                in_memory=ticket.in_memory,
                status="PENDING_REVIEW",
                expiration="PENDING_APPROVAL",
                ticket_ref=ticket.id,
            )
            created_entries.append(entry)

            # Update existing entry or append
            updated = False
            for idx, item in enumerate(vulnerabilities):
                if (
                    item.get("cve_id") == entry.cve_id
                    and item.get("package_name") == entry.package_name
                    and item.get("host") == entry.host
                ):
                    vulnerabilities[idx] = entry.model_dump()
                    updated = True
                    break

            if not updated:
                vulnerabilities.append(entry.model_dump())

        data["vulnerabilities"] = vulnerabilities
        data["total_tracked"] = len(vulnerabilities)
        data["pending_review"] = sum(
            1 for v in vulnerabilities if v.get("status") == "PENDING_REVIEW"
        )
        data["active_exceptions"] = sum(
            1 for v in vulnerabilities if v.get("status") == "APPROVED"
        )

        self._save_json_register(data)
        self._sync_markdown_register(vulnerabilities)
        logger.info(
            "Recorded batch of %d vulnerabilities in register", len(created_entries)
        )
        return created_entries

    def record_pending_exception(self, ticket: ExceptionTicket) -> RegisterEntry:
        """Add or update an entry in the register with PENDING_REVIEW status."""
        entries = self.record_pending_exceptions_batch([ticket])
        return entries[0]

    def _load_json_register(self) -> dict:
        """Load JSON register or return empty baseline."""
        if self.json_path.exists():
            try:
                with open(self.json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as err:
                logger.warning(
                    "Failed to parse %s (%s); initializing fresh registry",
                    self.json_path,
                    err,
                )
        return {
            "last_updated": "",
            "total_tracked": 0,
            "active_exceptions": 0,
            "pending_review": 0,
            "vulnerabilities": [],
        }

    def _save_json_register(self, data: dict):
        """Save updated JSON register."""
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _sync_markdown_register(self, vulnerabilities: list[dict]):
        """Render updated Markdown table for vulnerability_register.md."""
        rows = []
        for v in sorted(
            vulnerabilities,
            key=lambda x: (x.get("status") != "PENDING_REVIEW", x.get("cve_id")),
        ):
            in_ram_str = "YES" if v.get("in_memory") else "NO"
            ticket_link = (
                f"[{v.get('ticket_ref')}](../tickets/{v.get('ticket_ref')}.md)"
            )
            rows.append(
                f"| `{v.get('cve_id')}` | `{v.get('package_name')}` | `{v.get('installed_version')}` | "
                f"`{v.get('host')}` | {v.get('cvss_base')} | {v.get('epss_score'):.4f} | "
                f"{in_ram_str} | **{v.get('status')}** | `{v.get('expiration')}` | {ticket_link} |"
            )

        table_body = (
            "\n".join(rows)
            if rows
            else "| *No active vulnerabilities recorded* | - | - | - | - | - | - | - | - | - |"
        )

        content = f"""# Master Vulnerability & Risk Acceptance Register

This register is the single source of truth for all tracked vulnerabilities, risk exception requests, and governance approvals across the Oakai Security fleet.

Automatically maintained by autonomous micro-agents:
- **Requester Agent**: [`vuln-exception-requester`](https://github.com/oakai-security/vuln-exception-requester)
- **Approver Agent**: [`vuln-exception-approver`](https://github.com/oakai-security/vuln-exception-approver)
- **Architecture Spec**: [`SPEC-020`](file:///home/curt/dev/docs/specs/020-vulnerability-exception-and-remediation-governance.md)

---

## Active Vulnerability Index

| CVE ID | Package | Version | Host / Target | CVSS | EPSS | In RAM? | Status | Expiration | Ticket Reference |
|---|---|---|---|---|---|---|---|---|---|
{table_body}

---

## Status Definitions
- `PENDING_REVIEW`: Exception requested by `vuln-exception-requester`; awaiting governance review.
- `APPROVED`: Evaluated and approved by `vuln-exception-approver` (EPSS < 0.05 and in_memory is False).
- `REJECTED`: Exception rejected (EPSS >= 0.05 or resident in RAM); 7-day remediation SLA active.
- `REVOKED`: Previously approved exception revoked due to real-world EPSS spike (>= 0.05).
- `RESOLVED`: Upstream patch applied or package safely purged.
"""
        self.md_path.write_text(content, encoding="utf-8")
