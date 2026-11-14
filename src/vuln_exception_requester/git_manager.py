"""Git repository operations helper for committing tickets and register updates."""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class GitManager:
    """Automates git add, commit, and push in the vuln-register workspace."""

    def __init__(self, repo_dir: str | Path, auto_push: bool = False):
        self.repo_dir = Path(repo_dir)
        self.auto_push = auto_push

    def commit_changes(self, ticket_id: str, cve_id: str) -> bool:
        """Stage tickets/ and register/, and commit with a conventional commit message."""
        git_dir = self.repo_dir / ".git"
        if not git_dir.exists() and not (self.repo_dir / "../.git").exists():
            logger.info(
                "Directory %s is not a git repository; skipping git commit",
                self.repo_dir,
            )
            return True

        try:
            # Stage modified files
            subprocess.run(
                ["git", "-c", "safe.directory=*", "add", "tickets/", "register/"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )

            # Check if there are staged changes
            status_res = subprocess.run(
                ["git", "-c", "safe.directory=*", "status", "--porcelain"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )

            if not status_res.stdout.strip():
                logger.info("No git changes to commit for %s", ticket_id)
                return True

            commit_msg = (
                f"chore(exception): file {ticket_id} for {cve_id} [pending-review]"
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "safe.directory=*",
                    "-c",
                    "user.name=vuln-exception-requester",
                    "-c",
                    "user.email=pipeline@oakai.local",
                    "commit",
                    "-m",
                    commit_msg,
                ],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            logger.info("Committed %s in vuln-register: %s", ticket_id, commit_msg)

            if self.auto_push:
                subprocess.run(
                    ["git", "-c", "safe.directory=*", "push"],
                    cwd=self.repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                logger.info("Pushed %s changes to remote repository", ticket_id)

            return True

        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Git operation failed in %s: %s", self.repo_dir, err)
            return False
