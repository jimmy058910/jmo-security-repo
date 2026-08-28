"""Single repository workflow."""

from __future__ import annotations

from typing import Any

from .base_flow import BaseWizardFlow
from .profile_config import PROFILES, get_profile_warning


class RepoFlow(BaseWizardFlow):
    """Scan single repository workflow."""

    def detect_targets(self) -> dict[str, list]:
        """Detect repositories in current directory.

        Returns:
            Dictionary with 'repos' key containing list of repository paths
        """
        return {"repos": self.detector.detect_repos()}

    def prompt_user(self) -> dict[str, Any]:
        """Prompt for profile and artifact generation options.

        Returns:
            Dictionary with user selections
        """
        self.prompter.print_header("Repository Security Scan", icon="package")

        # Display detected repositories
        self._print_detected_repos(self.detected_targets)

        # Profile selection with recommendations. Both the descriptions and the
        # choices come from PROFILES, which derives its tool counts from
        # PROFILE_TOOLS -- the hardcoded copy here had drifted to the wrong
        # counts and omitted `slim` entirely (#721).
        profile_info = [
            f"{key}: {spec['description']}, {spec['est_time']}"
            for key, spec in PROFILES.items()
        ]
        self.prompter.print_summary_box("📊 Profile Options", profile_info)

        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=list(PROFILES),
            default="balanced",
        )

        # Show profile-specific warnings (e.g., deep profile first-run timing)
        warning = get_profile_warning(profile)
        if warning:
            print()  # Add spacing
            self.prompter.print_warning(warning)

        # Ask about artifact generation
        self.prompter.print_info(
            "Artifacts: Makefile targets, GitHub Actions workflows, shell scripts"
        )
        emit_artifacts = self.prompter.prompt_yes_no(
            "Generate reusable artifacts?", default=True
        )

        return {"profile": profile, "emit_artifacts": emit_artifacts}

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
            options: User selections (profile, artifacts)

        Returns:
            Command list
        """
        cmd = ["jmo", "scan", "--profile-name", options["profile"]]

        if targets["repos"]:
            # Use first detected repo
            repo = targets["repos"][0]
            cmd.extend(["--repo", str(repo)])

        return cmd
