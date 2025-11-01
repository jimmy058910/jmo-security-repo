"""Local cron installer for JMo Security scheduled scans.

Installs ScanSchedule objects to system crontab on Linux/macOS.
Windows is not supported (use GitHub Actions or GitLab CI instead).
"""

import platform
import subprocess
from typing import List

from scripts.core.schedule_manager import ScanSchedule


class UnsupportedPlatformError(Exception):
    """Platform does not support local cron."""

    pass


class CronNotAvailableError(Exception):
    """Cron is not available on this system."""

    pass


class CronInstallError(Exception):
    """Failed to install cron entry."""

    pass


class CronInstaller:
    """Install ScanSchedule to system crontab (Linux/macOS only)."""

    MARKER_START = "# JMo Security Schedule: "
    MARKER_END = "# End JMo Schedule"

    def __init__(self):
        """Initialize the cron installer.

        Raises:
            UnsupportedPlatformError: If platform is not Linux or macOS
        """
        self.platform = platform.system()
        if self.platform not in ("Linux", "Darwin"):
            raise UnsupportedPlatformError(
                f"Local cron not supported on {self.platform}. "
                f"Use GitHub Actions: jmo schedule export --backend github-actions"
            )

    def install(self, schedule: ScanSchedule) -> bool:
        """Install schedule to crontab.

        Args:
            schedule: ScanSchedule object to install

        Returns:
            bool: True if installation successful

        Raises:
            CronNotAvailableError: If crontab command not found
            CronInstallError: If crontab installation fails

        Example:
            >>> installer = CronInstaller()
            >>> installer.install(schedule)
            True
        """
        # Get current crontab
        current = self._get_crontab()

        # Remove any existing entries for this schedule
        current = self._remove_schedule_entries(current, schedule.metadata.name)

        # Generate and append new entry
        entry = self._generate_cron_entry(schedule)
        current.append(entry)

        # Install updated crontab
        return self._set_crontab(current)

    def uninstall(self, schedule_name: str) -> bool:
        """Remove schedule from crontab.

        Args:
            schedule_name: Name of schedule to remove

        Returns:
            bool: True if removal successful, False if not found

        Raises:
            CronNotAvailableError: If crontab command not found
            CronInstallError: If crontab update fails

        Example:
            >>> installer = CronInstaller()
            >>> installer.uninstall("nightly-deep")
            True
        """
        current = self._get_crontab()
        filtered = self._remove_schedule_entries(current, schedule_name)

        if len(filtered) == len(current):
            return False  # Not found

        return self._set_crontab(filtered)

    def list_installed(self) -> List[str]:
        """List all JMo schedules in crontab.

        Returns:
            list: List of schedule names

        Raises:
            CronNotAvailableError: If crontab command not found

        Example:
            >>> installer = CronInstaller()
            >>> installer.list_installed()
            ['nightly-deep', 'weekly-balanced']
        """
        current = self._get_crontab()
        schedules = []

        for line in current:
            if line.startswith(self.MARKER_START):
                name = line[len(self.MARKER_START) :].strip()
                schedules.append(name)

        return schedules

    def _get_crontab(self) -> List[str]:
        """Get current crontab as list of lines.

        Returns:
            list: List of crontab lines (empty if no crontab)

        Raises:
            CronNotAvailableError: If crontab command not found
        """
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                return (
                    result.stdout.strip().split("\n") if result.stdout.strip() else []
                )
            return []
        except FileNotFoundError:
            raise CronNotAvailableError("crontab command not found")

    def _set_crontab(self, lines: List[str]) -> bool:
        """Set crontab from list of lines.

        Args:
            lines: List of crontab lines

        Returns:
            bool: True if successful

        Raises:
            CronInstallError: If crontab installation fails
        """
        content = "\n".join(lines) + "\n"

        try:
            result = subprocess.run(
                ["crontab", "-"],
                input=content,
                text=True,
                capture_output=True,
                check=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            raise CronInstallError(f"Failed to install crontab: {e.stderr}")

    def _remove_schedule_entries(
        self, lines: List[str], schedule_name: str
    ) -> List[str]:
        """Remove all lines for a specific schedule.

        Uses marker-based approach to safely remove entries without
        affecting other cron jobs.

        Args:
            lines: List of crontab lines
            schedule_name: Name of schedule to remove

        Returns:
            list: Filtered list of crontab lines
        """
        filtered = []
        skip = False

        for line in lines:
            if line.startswith(f"{self.MARKER_START}{schedule_name}"):
                skip = True
                continue
            elif skip and line.startswith(self.MARKER_END):
                skip = False
                continue
            elif not skip:
                filtered.append(line)

        return filtered

    def _generate_cron_entry(self, schedule: ScanSchedule) -> str:
        """Generate cron entry for schedule.

        Format:
            # JMo Security Schedule: nightly-deep
            0 2 * * * jmo scan --profile deep --repos-dir ~/repos --results-dir ~/jmo-results/$(date +%Y-%m-%d)
            # End JMo Schedule

        Args:
            schedule: ScanSchedule object

        Returns:
            str: Multi-line cron entry with markers
        """
        spec = schedule.spec.jobTemplate

        # Build jmo command
        jmo_cmd = f"jmo scan --profile {spec.profile}"

        # Add targets
        targets = spec.targets

        # 1. Repositories
        if "repositories" in targets:
            repos = targets["repositories"]
            if "repo" in repos:
                jmo_cmd += f" --repo {repos['repo']}"
            if "repos_dir" in repos:
                jmo_cmd += f" --repos-dir {repos['repos_dir']}"

        # 2. Container Images
        if "images" in targets:
            for image in targets["images"]:
                jmo_cmd += f" --image {image}"

        # 3. IaC Files
        if "iac" in targets:
            iac = targets["iac"]
            if "terraform_state" in iac:
                jmo_cmd += f" --terraform-state {iac['terraform_state']}"
            if "cloudformation" in iac:
                jmo_cmd += f" --cloudformation {iac['cloudformation']}"
            if "k8s_manifest" in iac:
                jmo_cmd += f" --k8s-manifest {iac['k8s_manifest']}"

        # 4. Web URLs
        if "web" in targets:
            web = targets["web"]
            if "urls" in web:
                for url in web["urls"]:
                    jmo_cmd += f" --url {url}"
            if "api_spec" in web:
                jmo_cmd += f" --api-spec {web['api_spec']}"

        # 5. GitLab Repos (requires token from environment)
        if "gitlab" in targets:
            gitlab = targets["gitlab"]
            if "repo" in gitlab:
                jmo_cmd += f" --gitlab-repo {gitlab['repo']}"
            if "group" in gitlab:
                jmo_cmd += f" --gitlab-group {gitlab['group']}"
            # Token expected in environment variable GITLAB_TOKEN

        # 6. Kubernetes Clusters (requires kubectl config)
        if "kubernetes" in targets:
            k8s = targets["kubernetes"]
            if "context" in k8s:
                jmo_cmd += f" --k8s-context {k8s['context']}"
            if "namespace" in k8s:
                jmo_cmd += f" --k8s-namespace {k8s['namespace']}"
            elif k8s.get("all_namespaces"):
                jmo_cmd += " --k8s-all-namespaces"

        # Add results dir with date expansion
        results_base = spec.results.get("base_dir", "~/jmo-results")
        jmo_cmd += f" --results-dir {results_base}/$(date +%Y-%m-%d)"

        # Add options
        opts = spec.options
        if opts.get("allow_missing_tools"):
            jmo_cmd += " --allow-missing-tools"
        if "threads" in opts:
            jmo_cmd += f" --threads {opts['threads']}"
        if "fail_on" in opts:
            jmo_cmd += f" --fail-on {opts['fail_on']}"

        # Build cron line
        cron_schedule = schedule.spec.schedule

        # Multi-line entry with markers
        entry = f"""
{self.MARKER_START}{schedule.metadata.name}
{cron_schedule} {jmo_cmd}
{self.MARKER_END}
""".strip()

        return entry
