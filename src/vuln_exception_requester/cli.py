"""Command line interface for vuln-exception-requester."""

import argparse
import json
import logging
from pathlib import Path

from .git_manager import GitManager
from .register_manager import RegisterManager
from .schemas import UnresolvedFindingInput
from .socket_server import (
    DEFAULT_APPROVE_SOCKET,
    DEFAULT_REGISTER_REPO,
    DEFAULT_REQUEST_SOCKET,
    UdsRequestServer,
)
from .ticket_writer import TicketWriter


def main():
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Autonomous Vulnerability Exception Requester"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server command
    serve_parser = subparsers.add_parser(
        "serve", help="Start UDS exception requester server"
    )
    serve_parser.add_argument(
        "--socket", default=DEFAULT_REQUEST_SOCKET, help="Path to listen socket"
    )
    serve_parser.add_argument(
        "--downstream", default=DEFAULT_APPROVE_SOCKET, help="Path to approver socket"
    )
    serve_parser.add_argument(
        "--repo-path",
        default=DEFAULT_REGISTER_REPO,
        help="Path to vuln-register repository",
    )
    serve_parser.add_argument(
        "--auto-push", action="store_true", help="Auto push git commits to remote"
    )

    # File ticket command
    ticket_parser = subparsers.add_parser(
        "file-ticket", help="File a single exception ticket from CLI"
    )
    ticket_parser.add_argument("--cve", required=True, help="CVE ID")
    ticket_parser.add_argument("--package", required=True, help="Package name")
    ticket_parser.add_argument("--version", default="1.0.0", help="Installed version")
    ticket_parser.add_argument("--host", default="lejeune", help="Target host")
    ticket_parser.add_argument(
        "--cvss", type=float, default=7.5, help="Base CVSS score"
    )
    ticket_parser.add_argument("--epss", type=float, default=0.01, help="EPSS score")
    ticket_parser.add_argument(
        "--in-memory", action="store_true", help="Whether resident in RAM"
    )
    ticket_parser.add_argument(
        "--reason", default="Manual exception request", help="Justification rationale"
    )
    ticket_parser.add_argument(
        "--repo-path",
        default=DEFAULT_REGISTER_REPO,
        help="Path to vuln-register repository",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if args.command == "serve":
        server = UdsRequestServer(
            socket_path=args.socket,
            downstream_socket=args.downstream,
            register_repo_path=args.repo_path,
            auto_push=args.auto_push,
        )
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()

    elif args.command == "file-ticket":
        repo_dir = Path(args.repo_path)
        writer = TicketWriter(repo_dir / "tickets")
        reg_mgr = RegisterManager(repo_dir / "register")
        git_mgr = GitManager(repo_dir)

        finding = UnresolvedFindingInput(
            cve_id=args.cve,
            package_name=args.package,
            installed_version=args.version,
            host=args.host,
            cvss_base=args.cvss,
            epss_score=args.epss,
            epss_percentile=args.epss,
            in_memory=args.in_memory,
            threat_level="MEDIUM" if not args.in_memory else "HIGH",
            verdict_rationale=args.reason,
            remediation_attempt_summary="Manual CLI submission",
        )

        ticket, path = writer.create_exception_ticket(finding)
        reg_mgr.record_pending_exception(ticket)
        git_mgr.commit_changes(ticket.id, ticket.cve_id)

        print(json.dumps(ticket.model_dump(), indent=2))
        print(f"Ticket written to: {path}")


if __name__ == "__main__":
    main()
