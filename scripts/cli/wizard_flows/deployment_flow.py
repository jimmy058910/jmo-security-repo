"""Pre-deployment security checklist workflow."""

from typing import Any, Dict, List

from .base_flow import BaseWizardFlow


class DeploymentFlow(BaseWizardFlow):
    """Pre-deployment security validation workflow."""

    def detect_targets(self) -> Dict[str, List]:
        """Detect deployment-relevant targets.

        Returns:
            Dictionary with images, IaC, and web URLs
        """
        return {
            "images": self.detector.detect_images(),
            "iac": self.detector.detect_iac(),
            "web": self.detector.detect_web_apps(),
        }

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for deployment-specific options.

        Returns:
            Dictionary with selections
        """
        # Use balanced profile for pre-deployment by default
        profile = self.prompter.prompt_choice(
            "Select scan profile (pre-deployment typically uses 'balanced'):",
            choices=["balanced", "deep"],
            default="balanced",
        )

        # Ask about failure threshold
        fail_threshold = self.prompter.prompt_choice(
            "Fail deployment on which severity?",
            choices=["CRITICAL", "HIGH", "MEDIUM"],
            default="HIGH",
        )

        return {"profile": profile, "fail_on": fail_threshold}

    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build pre-deployment scan command.

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
            options["fail_on"],
        ]

        # Add images (critical for deployment)
        if targets["images"]:
            for image in targets["images"][:3]:  # Limit to 3 images
                cmd.extend(["--image", image])

        # Add IaC files (infrastructure validation)
        if targets["iac"]:
            for iac_file in targets["iac"][:5]:
                cmd.extend(["--terraform-state", str(iac_file)])

        # Add web URLs (for DAST)
        if targets["web"]:
            cmd.extend(["--url", targets["web"][0]])

        return cmd
