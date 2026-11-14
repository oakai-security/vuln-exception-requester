# vuln-exception-requester

Autonomous vulnerability exception requester micro-agent developed under the `@oakai-security` organization.

Part of the **Autonomous Vulnerability Remediation, Exception & Governance Pipeline** ([SPEC-020](file:///home/curt/dev/docs/specs/020-vulnerability-exception-and-remediation-governance.md)).

---

## Capabilities & Architecture

Built strictly according to the **Single Responsibility Principle (SRP)**:
1. **Unfixable CVE Ingestion**: Receives unfixable and unremovable vulnerability findings from `vuln-patch-analyst`.
2. **Ticket Generation**: Scaffolds formatted markdown tickets (`tickets/EXC-XXXX.md`) with YAML frontmatter in the dedicated [`vuln-register`](https://github.com/oakai-security/vuln-register) repository.
3. **Register Management**: Syncs both `register/vulnerability_register.json` and living table `register/vulnerability_register.md` with status `PENDING_REVIEW`.
4. **Git Operations**: Automatically commits changes to the register repository or mounted worktree.
5. **Downstream IPC Routing**: Transmits filed ticket details over `/run/oakai/approve.sock` to `vuln-exception-approver`.
6. **Unix Domain Socket (UDS) Server**: Exposes `/run/oakai/request.sock` with `SO_PEERCRED` caller verification.

---

## Installation & Local Development

### Requirements
- Python 3.11+
- `uv` package manager

### Setup
```bash
# Clone and sync virtual environment
uv sync

# Run tests
uv run pytest -v

# Run linter
uv run ruff check .
```

---

## Usage

### 1. File Exception Ticket via CLI
```bash
uv run vuln-exception-requester file-ticket \
  --cve CVE-2024-38077 \
  --package libc6 \
  --version 2.36 \
  --cvss 9.8 \
  --epss 0.008 \
  --reason "Not resident in active process RAM"
```

### 2. Start UDS Exception Requester Server Daemon
```bash
uv run vuln-exception-requester serve \
  --socket /run/oakai/request.sock \
  --downstream /run/oakai/approve.sock \
  --repo-path /home/curt/dev/repos/vuln-register
```

---

## Container Deployment
```bash
podman build -t oakai/vuln-exception-requester:latest .
podman run -d --name vuln-exception-requester \
  -v /run/oakai:/run/oakai:rw \
  -v /home/curt/dev/repos/vuln-register:/repo:rw \
  oakai/vuln-exception-requester:latest
```
