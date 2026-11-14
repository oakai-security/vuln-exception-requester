"""Unix Domain Socket server receiving unfixable CVEs and filing exception tickets."""

import json
import logging
import os
import socket
import struct
from pathlib import Path

from pydantic import ValidationError

from .git_manager import GitManager
from .register_manager import RegisterManager
from .schemas import ExceptionTicket, UnresolvedFindingInput
from .ticket_writer import TicketWriter

logger = logging.getLogger(__name__)

DEFAULT_REQUEST_SOCKET = os.environ.get("UDS_REQUEST_SOCKET", "/run/oakai/request.sock")
DEFAULT_APPROVE_SOCKET = os.environ.get("UDS_APPROVE_SOCKET", "/run/oakai/approve.sock")
DEFAULT_REGISTER_REPO = os.environ.get(
    "VULN_REGISTER_PATH", "/home/curt/dev/repos/vuln-register"
)


class UdsRequestServer:
    """UDS server that receives unfixable CVEs, writes tickets, and notifies approver."""

    def __init__(
        self,
        socket_path: str = DEFAULT_REQUEST_SOCKET,
        downstream_socket: str = DEFAULT_APPROVE_SOCKET,
        register_repo_path: str = DEFAULT_REGISTER_REPO,
        auto_push: bool = False,
    ):
        self.socket_path = socket_path
        self.downstream_socket = downstream_socket
        self.repo_dir = Path(register_repo_path)
        self.ticket_writer = TicketWriter(self.repo_dir / "tickets")
        self.register_manager = RegisterManager(self.repo_dir / "register")
        self.git_manager = GitManager(self.repo_dir, auto_push=auto_push)
        self._running = False
        self._server_socket: socket.socket | None = None

    def start(self, max_connections: int = 5):
        """Bind UDS socket and process incoming exception requests."""
        sock_file = Path(self.socket_path)
        sock_file.parent.mkdir(parents=True, exist_ok=True)

        if sock_file.exists():
            try:
                sock_file.unlink()
            except OSError as err:
                logger.warning("Failed to unlink stale socket: %s", err)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        try:
            os.chmod(self.socket_path, 0o660)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError as err:
            logger.warning("Could not set socket permissions to 0660: %s", err)

        self._server_socket.listen(max_connections)
        self._running = True
        logger.info("vuln-exception-requester listening on %s", self.socket_path)

        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                self._handle_client(conn)
            except (OSError, KeyboardInterrupt) as err:
                if self._running:
                    logger.error("Socket error: %s", err)
                break

    def stop(self):
        """Stop server and clean up socket file."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        logger.info("vuln-exception-requester stopped")

    def _handle_client(self, conn: socket.socket):
        """Process incoming findings, scaffold tickets, update register, and forward."""
        with conn:
            peer_info = self._get_peer_credentials(conn)
            logger.info("Accepted connection from: %s", peer_info)

            buffer = []
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buffer.append(chunk.decode("utf-8", errors="ignore"))

            raw_body = "".join(buffer).strip()
            if not raw_body:
                return

            try:
                parsed = json.loads(raw_body)
                items = parsed if isinstance(parsed, list) else [parsed]

                filed_tickets: list[ExceptionTicket] = []
                for item in items:
                    # Handle both raw finding dictionary and wrapper from patch analyst
                    finding_dict = item.get("finding", item)
                    remediation_summary = item.get("remediation", {}).get(
                        "action_summary", ""
                    )

                    finding = UnresolvedFindingInput(
                        cve_id=finding_dict["cve_id"],
                        package_name=finding_dict["package_name"],
                        installed_version=finding_dict["installed_version"],
                        host=finding_dict.get("host", "lejeune"),
                        cvss_base=finding_dict["cvss_base"],
                        epss_score=finding_dict["epss_score"],
                        epss_percentile=finding_dict.get(
                            "epss_percentile", finding_dict["epss_score"]
                        ),
                        in_memory=finding_dict["in_memory"],
                        threat_level=finding_dict["threat_level"],
                        verdict_rationale=finding_dict["verdict_rationale"],
                        remediation_attempt_summary=remediation_summary,
                    )

                    ticket, _ = self.ticket_writer.create_exception_ticket(finding)
                    self.register_manager.record_pending_exception(ticket)
                    self.git_manager.commit_changes(ticket.id, ticket.cve_id)
                    filed_tickets.append(ticket)

                # Forward filed tickets downstream to Approver Agent
                if filed_tickets and os.path.exists(self.downstream_socket):
                    self._forward_to_approver(filed_tickets)

                response = [t.model_dump() for t in filed_tickets]
                conn.sendall(json.dumps(response, indent=2).encode("utf-8"))

            except (
                json.JSONDecodeError,
                ValidationError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ) as err:
                logger.error("Error processing exception request: %s", err)
                conn.sendall(json.dumps({"error": str(err)}).encode("utf-8"))

    def _forward_to_approver(self, tickets: list[ExceptionTicket]):
        """Forward filed exception requests over UDS to vuln-exception-approver."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.downstream_socket)
                payload = [t.model_dump() for t in tickets]
                client.sendall(json.dumps(payload).encode("utf-8"))
                client.shutdown(socket.SHUT_WR)
                client.recv(8192)
                logger.info(
                    "Forwarded %d pending tickets to approver socket", len(tickets)
                )
        except OSError as err:
            logger.warning(
                "Approver socket %s unreachable: %s", self.downstream_socket, err
            )

    def _get_peer_credentials(self, conn: socket.socket) -> str:
        """Inspect SO_PEERCRED on Linux."""
        try:
            creds = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", creds)
            return f"PID={pid}, UID={uid}, GID={gid}"
        except (AttributeError, OSError):
            return "unknown (SO_PEERCRED unavailable)"
