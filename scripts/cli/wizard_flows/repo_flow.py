"""Single repository workflow."""

from pathlib import Path
from typing import Any, Dict, List

from .base_flow import BaseWizardFlow


class RepoFlow(BaseWizardFlow):
    """Scan single repository workflow."""

    def detect_targets(self) -> Dict[str, List]:
        """Detect repositories in current directory.

        Returns:
            Dictionary with 'repos' key containing list of repository paths
        """
        return {"repos": self.detector.detect_repos()}

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for profile and artifact generation options.

        Returns:
            Dictionary with user selections
        """
        # Select profile
        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=["fast", "balanced", "deep"],
            default="balanced",
        )

        # Ask about artifact generation
        emit_artifacts = self.prompter.prompt_yes_no(
            "Generate reusable artifacts (Makefile, GHA)?", default=True
        )

        return {"profile": profile, "emit_artifacts": emit_artifacts}

    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build jmo scan command for single repository.

        Args:
            targets: Detected targets (repos)
            options: User selections (profile, artifacts)

        Returns:
            Command list
        """
        cmd = ["jmo", "scan", "--profile", options["profile"]]

        if targets["repos"]:
            # Use first detected repo
            repo = targets["repos"][0]
            cmd.extend(["--repo", str(repo)])

        return cmd
