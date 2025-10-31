"""CI/CD security audit workflow."""

from pathlib import Path
from typing import Any, Dict, List

from .base_flow import BaseWizardFlow


class CICDFlow(BaseWizardFlow):
    """CI/CD pipeline security audit workflow."""

    def detect_targets(self) -> Dict[str, List]:
        """Detect CI/CD-relevant targets.

        Returns:
            Dictionary with repos, images, and IaC
        """
        return {
            "repos": self.detector.detect_repos(),
            "images": self.detector.detect_images(),
            "iac": self.detector.detect_iac(),
        }

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for CI/CD-specific options.

        Returns:
            Dictionary with selections
        """
        # Use fast profile for CI/CD by default
        profile = self.prompter.prompt_choice(
            "Select scan profile (CI/CD typically uses 'fast'):",
            choices=["fast", "balanced"],
            default="fast",
        )

        # Ask about workflow generation
        emit_workflow = self.prompter.prompt_yes_no(
            "Generate GitHub Actions workflow?", default=True
        )

        return {"profile": profile, "emit_workflow": emit_workflow}

    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build CI/CD-optimized scan command.

        Args:
            targets: Detected targets
            options: User selections

        Returns:
            Command list
        """
        cmd = [
            "jmo",
            "ci",
            "--profile",
            options["profile"],
            "--fail-on",
            "HIGH",  # Fail on high severity in CI/CD
        ]

        # Add repositories
        if targets["repos"]:
            cmd.extend(["--repos-dir", "."])

        # Add images
        if targets["images"]:
            images_file = Path("ci-images.txt")
            images_file.write_text("\n".join(targets["images"]))
            cmd.extend(["--images-file", str(images_file)])

        return cmd
