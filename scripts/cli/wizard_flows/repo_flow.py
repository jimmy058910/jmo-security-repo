"""Single repository workflow."""

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
        self.prompter.print_header("Repository Security Scan", icon="package")

        # Display detected repositories
        self._print_detected_repos(self.detected_targets)

        # Profile selection with recommendations
        profile_info = [
            "fast: 3 tools, 5-8 minutes (pre-commit, quick checks)",
            "balanced: 8 tools, 15-20 minutes (CI/CD, regular audits)",
            "deep: 12 tools, 30-60 minutes (security audits, compliance)",
        ]
        self.prompter.print_summary_box("📊 Profile Options", profile_info)

        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=["fast", "balanced", "deep"],
            default="balanced",
        )

        # Ask about artifact generation
        self.prompter.print_info(
            "Artifacts: Makefile targets, GitHub Actions workflows, shell scripts"
        )
        emit_artifacts = self.prompter.prompt_yes_no(
            "Generate reusable artifacts?", default=True
        )

        return {"profile": profile, "emit_artifacts": emit_artifacts}

    def _print_detected_repos(self, targets: Dict) -> None:
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
