"""Unit test suite for vuln-exception-requester micro-agent."""

import json
import socket
import tempfile
import threading
from pathlib import Path

from vuln_exception_requester.register_manager import RegisterManager
from vuln_exception_requester.schemas import ExceptionTicket, UnresolvedFindingInput
from vuln_exception_requester.socket_server import UdsRequestServer
from vuln_exception_requester.ticket_writer import TicketWriter


def test_ticket_writer_increments_id():
    """Verify TicketWriter correctly increments ticket IDs from EXC-0001."""
    with tempfile.TemporaryDirectory() as temp_dir:
        writer = TicketWriter(temp_dir)

        finding1 = UnresolvedFindingInput(
            cve_id="CVE-2024-0001",
            package_name="libone",
            installed_version="1.0",
            cvss_base=7.0,
            epss_score=0.01,
            epss_percentile=0.40,
            in_memory=False,
            threat_level="MEDIUM",
            verdict_rationale="Test rationale 1",
        )
        ticket1, path1 = writer.create_exception_ticket(finding1)
        assert ticket1.id == "EXC-0001"
        assert path1.exists()

        finding2 = UnresolvedFindingInput(
            cve_id="CVE-2024-0002",
            package_name="libtwo",
            installed_version="2.0",
            cvss_base=8.0,
            epss_score=0.02,
            epss_percentile=0.50,
            in_memory=False,
            threat_level="MEDIUM",
            verdict_rationale="Test rationale 2",
        )
        ticket2, path2 = writer.create_exception_ticket(finding2)
        assert ticket2.id == "EXC-0002"
        assert path2.exists()


def test_register_manager_updates_json_and_markdown():
    """Verify RegisterManager syncs JSON and Markdown tables."""
    with tempfile.TemporaryDirectory() as temp_dir:
        reg_mgr = RegisterManager(temp_dir)

        ticket = ExceptionTicket(
            id="EXC-0001",
            cve_id="CVE-2024-38077",
            package_name="libsqlite3",
            installed_version="3.40.1",
            host="lejeune",
            cvss_base=9.8,
            epss_score=0.005,
            in_memory=False,
            threat_level="MEDIUM",
            status="PENDING_REVIEW",
            reason="Unreachable in RAM",
        )

        entry = reg_mgr.record_pending_exception(ticket)
        assert entry.cve_id == "CVE-2024-38077"
        assert entry.status == "PENDING_REVIEW"

        # Check JSON register
        with open(reg_mgr.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_tracked"] == 1
            assert data["pending_review"] == 1
            assert data["vulnerabilities"][0]["cve_id"] == "CVE-2024-38077"

        # Check Markdown register
        md_content = reg_mgr.md_path.read_text(encoding="utf-8")
        assert "CVE-2024-38077" in md_content
        assert "PENDING_REVIEW" in md_content
        assert "[EXC-0001]" in md_content


def test_uds_socket_roundtrip(mocker):
    """Verify IPC receiving unfixable finding, creating ticket, and updating register."""
    with tempfile.TemporaryDirectory() as temp_dir:
        req_sock = str(Path(temp_dir) / "test_req.sock")
        appr_sock = str(Path(temp_dir) / "test_appr.sock")
        repo_dir = Path(temp_dir) / "repo"
        repo_dir.mkdir()

        server = UdsRequestServer(
            socket_path=req_sock,
            downstream_socket=appr_sock,
            register_repo_path=str(repo_dir),
        )

        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        import time

        time.sleep(0.1)

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(req_sock)

        payload = [
            {
                "finding": {
                    "cve_id": "CVE-2024-38077",
                    "package_name": "libc6",
                    "installed_version": "2.36",
                    "cvss_base": 9.8,
                    "epss_score": 0.008,
                    "epss_percentile": 0.45,
                    "in_memory": False,
                    "threat_level": "MEDIUM",
                    "verdict_rationale": "Not resident in memory",
                },
                "remediation": {
                    "status": "UNRESOLVED_FORWARD",
                    "action_summary": "Package cannot be safely purged",
                },
            }
        ]
        client_sock.sendall(json.dumps(payload).encode("utf-8"))
        client_sock.shutdown(socket.SHUT_WR)

        response_raw = client_sock.recv(8192).decode("utf-8")
        client_sock.close()
        server.stop()

        filed = json.loads(response_raw)
        assert len(filed) == 1
        assert filed[0]["id"] == "EXC-0001"
        assert filed[0]["cve_id"] == "CVE-2024-38077"
        assert filed[0]["status"] == "PENDING_REVIEW"

        # Verify ticket file was written to repo/tickets/EXC-0001.md
        ticket_file = repo_dir / "tickets" / "EXC-0001.md"
        assert ticket_file.exists()
        assert "CVE-2024-38077" in ticket_file.read_text(encoding="utf-8")


def test_batch_request_processing(mocker):
    """Verify batch processing of multiple findings in a single atomic update."""
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = Path(temp_dir) / "repo"
        repo_dir.mkdir()
        reg_mgr = RegisterManager(repo_dir / "register")

        tickets = [
            ExceptionTicket(
                id=f"EXC-{i:04d}",
                cve_id=f"CVE-2024-{i:04d}",
                package_name=f"pkg-{i}",
                installed_version="1.0",
                host="lejeune",
                cvss_base=7.5,
                epss_score=0.01,
                in_memory=False,
                threat_level="LOW",
                status="PENDING_REVIEW",
                reason="Testing batch",
            )
            for i in range(1, 6)
        ]

        entries = reg_mgr.record_pending_exceptions_batch(tickets)
        assert len(entries) == 5

        with open(reg_mgr.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_tracked"] == 5
            assert data["pending_review"] == 5

        md = reg_mgr.md_path.read_text(encoding="utf-8")
        for i in range(1, 6):
            assert f"CVE-2024-{i:04d}" in md
