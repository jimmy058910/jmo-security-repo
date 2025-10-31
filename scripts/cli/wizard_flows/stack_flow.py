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
        """Prompt for profile selection with smart recommendations.

        Returns:
            Dictionary with profile selection and options
        """
        # Generate and display smart recommendations
        recommendations = self._generate_recommendations(self.detected_targets)
        if recommendations:
            self.prompter.print_summary_box("💡 Smart Recommendations", recommendations)

        # Profile selection
        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=["fast", "balanced", "deep"],
            default="balanced",
        )

        # Artifact generation option
        emit_artifacts = self.prompter.prompt_yes_no(
            "\nGenerate reusable artifacts (Makefile, GHA, docker-compose)?", default=True
        )

        # Parallel scanning option
        parallel_scan = self.prompter.prompt_yes_no(
            "Run scans in parallel (faster but more CPU)?", default=True
        )

        return {
            "profile": profile,
            "emit_artifacts": emit_artifacts,
            "parallel": parallel_scan,
        }

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

    def _generate_recommendations(self, targets: Dict) -> List[str]:
        """Generate smart recommendations based on detected targets.

        Args:
            targets: Detected targets dictionary

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Recommend container scanning if Dockerfile found but no images
        if self._has_dockerfile() and not targets["images"]:
            recommendations.append(
                "Found Dockerfile but no images detected. "
                "Consider building image first: 'docker build -t myapp .'"
            )

        # Recommend IaC scanning if terraform found but not initialized
        if self._has_terraform_dir() and not targets["iac"]:
            recommendations.append(
                "Found terraform/ directory. Consider initializing: "
                "'cd terraform && terraform init && terraform plan -out=tfplan'"
            )

        # Recommend GitLab scanning if .gitlab-ci.yml found
        if Path.cwd() / ".gitlab-ci.yml" in [Path.cwd() / ".gitlab-ci.yml"]:
            if (Path.cwd() / ".gitlab-ci.yml").exists():
                recommendations.append(
                    "Found .gitlab-ci.yml. Use '--gitlab-repo' to scan GitLab repositories."
                )

        # Recommend K8s scanning if kubernetes/ directory found
        if self._has_k8s_dir():
            recommendations.append(
                "Found kubernetes/ directory. Scan live cluster with '--k8s-context' for runtime security."
            )

        # Recommend GitHub Actions scanning if workflows found
        if self._has_github_workflows():
            recommendations.append(
                "Found GitHub Actions workflows. Consider CI/CD Security Audit workflow."
            )

        return recommendations

    def _has_dockerfile(self) -> bool:
        """Check if Dockerfile exists in current directory."""
        return len(list(Path.cwd().glob("**/Dockerfile*"))) > 0

    def _has_terraform_dir(self) -> bool:
        """Check if terraform/ directory exists."""
        return (Path.cwd() / "terraform").exists()

    def _has_k8s_dir(self) -> bool:
        """Check if kubernetes/ or k8s/ directory exists."""
        return (Path.cwd() / "kubernetes").exists() or (Path.cwd() / "k8s").exists()

    def _has_github_workflows(self) -> bool:
        """Check if .github/workflows/ exists."""
        workflows_dir = Path.cwd() / ".github" / "workflows"
        return workflows_dir.exists() and len(list(workflows_dir.glob("*.yml"))) > 0
