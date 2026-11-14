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

    def commit_batch(self, commit_msg: str) -> bool:
        """Stage tickets/ and register/, and commit the batch with a conventional commit message."""
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
                logger.info("No git changes to commit in batch")
                return True

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
            logger.info("Committed batch in vuln-register: %s", commit_msg)

            if self.auto_push:
                subprocess.run(
                    ["git", "-c", "safe.directory=*", "push"],
                    cwd=self.repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                logger.info("Pushed batch changes to remote repository")

            return True

        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Git batch operation failed in %s: %s", self.repo_dir, err)
            return False

    def commit_changes(self, ticket_id: str, cve_id: str) -> bool:
        """Stage tickets/ and register/, and commit with a conventional commit message."""
        commit_msg = (
            f"chore(exception): file {ticket_id} for {cve_id} [pending-review]"
        )
        return self.commit_batch(commit_msg)
