"""Pre-deployment security checklist workflow."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .base_flow import BaseWizardFlow


class DeploymentFlow(BaseWizardFlow):
    """Pre-deployment security validation workflow."""

    def detect_targets(self) -> dict[str, Any]:
        """Detect deployment-relevant targets.

        Returns:
            Dictionary with images, IaC, web URLs, and environment
        """
        return {
            "images": self.detector.detect_images(),
            "iac": self.detector.detect_iac(),
            "web": self.detector.detect_web_apps(),
            "environment": self._detect_environment(),
        }

    def prompt_user(self) -> dict[str, Any]:
        """Prompt for deployment-specific options with environment-aware recommendations.

        Returns:
            Dictionary with selections
        """
        self.prompter.print_header("Pre-Deployment Security Checklist", icon="rocket")

        # Display detected deployment targets
        self._print_detected_deployment_targets(self.detected_targets)

        # Environment selection with auto-detection
        detected_env = self.detected_targets.get("environment", "staging")
        self.prompter.print_info(f"Auto-detected environment: {detected_env}")
        environment = self.prompter.prompt_choice(
            "Deployment environment:",
            choices=["staging", "production"],
            default=str(detected_env) if detected_env else "staging",
        )

        # Production deployment warning
        if environment == "production":
            prod_requirements = [
                "Deep scan profile (comprehensive checks)",
                "Zero CRITICAL findings",
                "Compliance validation (OWASP, CWE, PCI DSS)",
                "All container images scanned",
                "Infrastructure-as-Code validated",
            ]
            self.prompter.print_summary_box(
                "⚠️  Production Deployment Requirements", prod_requirements
            )

        # Profile selection based on environment
        profile_default = "deep" if environment == "production" else "balanced"
        if environment == "production":
            self.prompter.print_warning(
                "Production deployments require 'deep' profile (30-60 min)"
            )
        else:
            self.prompter.print_info(
                "Staging deployments typically use 'balanced' profile (15-20 min)"
            )

        profile = self.prompter.prompt_choice(
            "Select scan profile:",
            choices=["balanced", "deep"],
            default=profile_default,
        )

        # Failure threshold based on environment
        fail_default = "CRITICAL" if environment == "production" else "HIGH"
        fail_threshold = self.prompter.prompt_choice(
            "Fail deployment on which severity?",
            choices=["CRITICAL", "HIGH", "MEDIUM"],
            default=fail_default,
        )

        return {
            "environment": environment,
            "profile": profile,
            "fail_on": fail_threshold,
        }

    def _print_detected_deployment_targets(self, targets: dict) -> None:
        """Print summary of detected deployment targets."""
        items = []

        if targets.get("images"):
            items.append(f"Container images: {len(targets['images'])} detected")
            for image in targets["images"][:3]:
                items.append(f"  → {image}")
            if len(targets["images"]) > 3:
                items.append(f"  ... and {len(targets['images']) - 3} more")

        if targets.get("iac"):
            items.append(f"IaC files: {len(targets['iac'])} detected")
            for iac_file in targets["iac"][:3]:
                items.append(f"  → {iac_file.name}")
            if len(targets["iac"]) > 3:
                items.append(f"  ... and {len(targets['iac']) - 3} more")

        if targets.get("web"):
            items.append(f"Web URLs: {len(targets['web'])} detected for DAST")
            for url in targets["web"][:3]:
                items.append(f"  → {url}")

        if items:
            self.prompter.print_summary_box("🔍 Detected Deployment Targets", items)
        else:
            self.prompter.print_warning("No deployment targets detected")

    def build_command(self, targets: dict, options: dict) -> list[str]:
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

    def _detect_environment(self) -> str:
        """Auto-detect deployment environment from various signals.

        Returns:
            Environment name ('staging' or 'production')
        """
        # Check environment variables
        env_vars = [
            os.getenv("ENVIRONMENT"),
            os.getenv("ENV"),
            os.getenv("NODE_ENV"),
            os.getenv("RAILS_ENV"),
            os.getenv("FLASK_ENV"),
        ]

        for env_var in env_vars:
            if env_var:
                env_lower = env_var.lower()
                if "prod" in env_lower:
                    return "production"
                elif "stag" in env_lower:
                    return "staging"

        # Check .env files
        env_file = Path.cwd() / ".env"
        if env_file.exists():
            try:
                content = env_file.read_text()
                if "ENVIRONMENT=production" in content or "ENV=production" in content:
                    return "production"
                elif "ENVIRONMENT=staging" in content or "ENV=staging" in content:
                    return "staging"
            except (FileNotFoundError, UnicodeDecodeError):
                pass

        # Check kubernetes manifests for namespace
        for k8s_file in Path.cwd().glob("**/k8s/**/*.yml"):
            try:
                content = k8s_file.read_text()
                if "namespace: production" in content:
                    return "production"
                elif "namespace: staging" in content:
                    return "staging"
            except (FileNotFoundError, UnicodeDecodeError):
                pass

        # Default to staging (safer default)
        return "staging"
