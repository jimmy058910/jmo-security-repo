"""Single repository workflow."""

from __future__ import annotations

from typing import Any

from .base_flow import BaseWizardFlow


class RepoFlow(BaseWizardFlow):
    """Scan single repository workflow."""

    def detect_targets(self) -> dict[str, list]:
        """Detect repositories in current directory.

        Returns:
            Dictionary with 'repos' key containing list of repository paths
        """
        return {"repos": self.detector.detect_repos()}

    def prompt_user(self) -> dict[str, Any]:
        """Prompt for artifact generation options.

        Returns:
            Dictionary with user selections
        """
        self.prompter.print_header("Repository Security Scan", icon="package")

        # Display detected repositories
        self._print_detected_repos(self.detected_targets)

        # Ask about artifact generation
        self.prompter.print_info(
            "Artifacts: Makefile targets, GitHub Actions workflows, shell scripts"
        )
        emit_artifacts = self.prompter.prompt_yes_no(
            "Generate reusable artifacts?", default=True
        )

        return {"emit_artifacts": emit_artifacts}

    def _print_detected_repos(self, targets: dict) -> None:
        """Print summary of detected repositories."""
        items = []

        if targets.get("repos"):
            items.append(f"Repositories: {len(targets['repos'])} detected")
            for repo in targets["repos"][:5]:
                items.append(f"  → {repo.name}")
            if len(targets["repos"]) > 5:
                items.append(f"  ... and {len(targets['repos']) - 5} more")

        if items:
            self.prompter.print_summary_box("🔍 Detected Repositories", items)
        else:
            self.prompter.print_warning("No repositories detected in current directory")

    def build_command(self, targets: dict, options: dict) -> list[str]:
        """Build jmo scan command for single repository.

        Args:
            targets: Detected targets (repos)
            options: User selections (artifacts)

        Returns:
            Command list
        """
        cmd = ["jmo", "scan"]

        if targets["repos"]:
            # Use first detected repo
            repo = targets["repos"][0]
            cmd.extend(["--repo", str(repo)])

        return cmd
