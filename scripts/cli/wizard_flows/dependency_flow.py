"""Dependency security audit workflow."""

from pathlib import Path
from typing import Any, Dict, List

from .base_flow import BaseWizardFlow


class DependencyFlow(BaseWizardFlow):
    """SBOM generation and dependency vulnerability scanning workflow."""

    def detect_targets(self) -> Dict[str, Any]:
        """Detect dependency-relevant targets.

        Returns:
            Dictionary with package_files, lock_files, and images
        """
        package_files = self.detector.detect_package_files()
        lock_files = self.detector.detect_lock_files()
        images = self.detector.detect_images()

        return {
            "package_files": package_files,
            "lock_files": lock_files,
            "images": images,
        }

    def prompt_user(self) -> Dict[str, Any]:
        """Prompt for dependency-specific options.

        Returns:
            Dictionary with selections
        """
        print("\n📦 Dependency Security Audit\n")

        # SBOM generation
        generate_sbom = self.prompter.prompt_yes_no(
            "Generate SBOM (Software Bill of Materials)?", default=True
        )

        # Vulnerability scanning
        scan_vulnerabilities = self.prompter.prompt_yes_no(
            "Scan for known vulnerabilities (CVEs)?", default=True
        )

        # License checking (optional, requires additional tooling)
        check_licenses = self.prompter.prompt_yes_no(
            "Check dependency licenses? (requires license-checker)", default=False
        )

        return {
            "generate_sbom": generate_sbom,
            "scan_vulns": scan_vulnerabilities,
            "check_licenses": check_licenses,
        }

    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build dependency audit scan command.

        Args:
            targets: Detected targets (package files, images)
            options: User selections (SBOM, vulns, licenses)

        Returns:
            Command list focused on syft + trivy for dependencies
        """
        # Use syft + trivy for dependency scanning
        cmd = ["jmo", "scan", "--profile", "balanced", "--tools", "syft", "trivy"]

        # Add repository for code dependencies
        cmd.extend(["--repo", str(Path.cwd())])

        # Add images for container dependencies
        if targets["images"]:
            images_file = Path("dependency-images.txt")
            images_file.write_text("\n".join(targets["images"]))
            cmd.extend(["--images-file", str(images_file)])

        return cmd

    def _print_detected_dependencies(self, targets: Dict) -> None:
        """Print summary of detected package managers and files."""
        items = []

        if targets["package_files"]:
            pkg_count = len(targets["package_files"])
            items.append(f"Package manifests: {pkg_count} detected")
            for pkg_file in targets["package_files"][:5]:  # Show first 5
                items.append(f"  → {pkg_file.name}")
            if pkg_count > 5:
                items.append(f"  ... and {pkg_count - 5} more")

        if targets["lock_files"]:
            lock_count = len(targets["lock_files"])
            items.append(f"Lock files: {lock_count} detected (reproducible scans)")
            for lock_file in targets["lock_files"][:3]:  # Show first 3
                items.append(f"  → {lock_file.name}")
            if lock_count > 3:
                items.append(f"  ... and {lock_count - 3} more")

        if targets["images"]:
            items.append(f"Container images: {len(targets['images'])} detected")

        if items:
            self.prompter.print_summary_box("🔍 Detected Dependency Files", items)
        else:
            self.prompter.print_warning("No dependency files detected")
