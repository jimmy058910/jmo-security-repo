"""CI/CD security audit workflow."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_flow import BaseWizardFlow


class CICDFlow(BaseWizardFlow):
    """CI/CD pipeline security audit workflow."""

    def detect_targets(self) -> Dict[str, Any]:
        """Detect CI/CD-relevant targets.

        Returns:
            Dictionary with CI pipeline files, images, and potential secrets
        """
        ci_dir = Path.cwd()

        # Detect CI pipeline files
        github_actions = list(ci_dir.glob(".github/workflows/*.yml")) + list(
            ci_dir.glob(".github/workflows/*.yaml")
        )
        gitlab_ci = ci_dir / ".gitlab-ci.yml" if (ci_dir / ".gitlab-ci.yml").exists() else None
        jenkinsfile = ci_dir / "Jenkinsfile" if (ci_dir / "Jenkinsfile").exists() else None

        # Detect images referenced in pipelines
        pipeline_images = self._detect_images_from_ci(github_actions, gitlab_ci, jenkinsfile)

        return {
            "github_actions": github_actions,
            "gitlab_ci": gitlab_ci,
            "jenkinsfile": jenkinsfile,
            "pipeline_images": pipeline_images,
            "repos": self.detector.detect_repos(),
            "images": self.detector.detect_images(),
            "iac": self.detector.detect_iac(),
        }

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for CI/CD-specific options.

        Returns:
            Dictionary with selections
        """
        print("\n🔒 CI/CD Security Audit\n")

        # Use fast profile for CI/CD by default
        profile = self.prompter.prompt_choice(
            "Select scan profile (CI/CD typically uses 'fast'):",
            choices=["fast", "balanced"],
            default="fast",
        )

        # Scan pipeline files
        scan_pipeline_files = self.prompter.prompt_yes_no(
            "\nScan pipeline files for secrets and misconfigurations?", default=True
        )

        # Scan pipeline images
        num_images = len(self.detected_targets.get("pipeline_images", []))
        if num_images > 0:
            scan_pipeline_images = self.prompter.prompt_yes_no(
                f"Scan {num_images} container images referenced in pipelines?", default=True
            )
        else:
            scan_pipeline_images = False

        # GitHub Actions permissions check
        has_gha = len(self.detected_targets.get("github_actions", [])) > 0
        if has_gha:
            check_permissions = self.prompter.prompt_yes_no(
                "Check GitHub Actions permissions (GITHUB_TOKEN scopes)?", default=True
            )
        else:
            check_permissions = False

        # Ask about workflow generation
        emit_workflow = self.prompter.prompt_yes_no(
            "\nGenerate GitHub Actions workflow?", default=True
        )

        return {
            "profile": profile,
            "scan_files": scan_pipeline_files,
            "scan_images": scan_pipeline_images,
            "check_permissions": check_permissions,
            "emit_workflow": emit_workflow,
        }

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

        # Scan pipeline files (repos) if requested
        if options.get("scan_files") and targets["repos"]:
            cmd.extend(["--repos-dir", "."])

        # Scan pipeline images if requested
        if options.get("scan_images") and targets.get("pipeline_images"):
            images_file = Path("pipeline-images.txt")
            images_file.write_text("\n".join(targets["pipeline_images"]))
            cmd.extend(["--images-file", str(images_file)])

        return cmd

    def _detect_images_from_ci(
        self,
        github_actions: List[Path],
        gitlab_ci: Optional[Path],
        jenkinsfile: Optional[Path],
    ) -> List[str]:
        """Extract container images referenced in CI pipeline files.

        Args:
            github_actions: List of GitHub Actions workflow files
            gitlab_ci: Path to .gitlab-ci.yml (if exists)
            jenkinsfile: Path to Jenkinsfile (if exists)

        Returns:
            List of image names found in pipelines
        """
        images = []

        # GitHub Actions: look for "image:" or "container:" fields
        for workflow_file in github_actions:
            try:
                content = workflow_file.read_text()
                # Match patterns like "image: nginx:latest" or "container: python:3.10"
                import re

                for match in re.finditer(
                    r"(?:image|container):\s*([\w/:@.-]+)", content, re.IGNORECASE
                ):
                    images.append(match.group(1))
            except (FileNotFoundError, UnicodeDecodeError):
                pass

        # GitLab CI: look for "image:" fields
        if gitlab_ci and gitlab_ci.exists():
            try:
                import yaml

                ci_config = yaml.safe_load(gitlab_ci.read_text())
                if isinstance(ci_config, dict):
                    # Global image
                    if "image" in ci_config:
                        img = ci_config["image"]
                        if isinstance(img, str):
                            images.append(img)
                        elif isinstance(img, dict) and "name" in img:
                            images.append(img["name"])

                    # Job-specific images
                    for job in ci_config.values():
                        if isinstance(job, dict) and "image" in job:
                            img = job["image"]
                            if isinstance(img, str):
                                images.append(img)
                            elif isinstance(img, dict) and "name" in img:
                                images.append(img["name"])
            except (FileNotFoundError, UnicodeDecodeError, yaml.YAMLError):
                pass

        # Jenkinsfile: look for "docker.image" or similar
        if jenkinsfile and jenkinsfile.exists():
            try:
                content = jenkinsfile.read_text()
                import re

                for match in re.finditer(r"docker\.image\(['\"]([^'\"]+)['\"]\)", content):
                    images.append(match.group(1))
            except (FileNotFoundError, UnicodeDecodeError):
                pass

        return list(set(images))  # Deduplicate
