"""Entire development stack workflow."""

from pathlib import Path
from typing import Any, Dict, List

from .base_flow import BaseWizardFlow


class EntireStackFlow(BaseWizardFlow):
    """Scan entire development stack (repos + images + IaC + web)."""

    def detect_targets(self) -> Dict[str, List]:
        """Detect all target types in current directory.

        Returns:
            Dictionary with all target types
        """
        return {
            "repos": self.detector.detect_repos(),
            "images": self.detector.detect_images(),
            "iac": self.detector.detect_iac(),
            "web": self.detector.detect_web_apps(),
        }

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for profile selection.

        Returns:
            Dictionary with profile selection
        """
        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=["fast", "balanced", "deep"],
            default="balanced",
        )

        return {"profile": profile}

    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build jmo scan command for entire stack.

        Args:
            targets: Detected targets (all types)
            options: User selections (profile)

        Returns:
            Command list
        """
        cmd = ["jmo", "scan", "--profile", options["profile"]]

        # Add repositories
        if targets["repos"]:
            cmd.extend(["--repos-dir", "."])

        # Add images
        if targets["images"]:
            images_file = Path("detected-images.txt")
            images_file.write_text("\n".join(targets["images"]))
            cmd.extend(["--images-file", str(images_file)])

        # Add IaC files (limit to first 5 to avoid command-line length issues)
        if targets["iac"]:
            for iac_file in targets["iac"][:5]:
                cmd.extend(["--terraform-state", str(iac_file)])

        # Add web URLs
        if targets["web"]:
            cmd.extend(["--url", targets["web"][0]])

        return cmd
