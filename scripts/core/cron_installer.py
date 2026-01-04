"""Local cron installer for JMo Security scheduled scans.

Installs ScanSchedule objects to system crontab on Linux/macOS.
Windows is not supported (use GitHub Actions or GitLab CI instead).

Security: All user inputs (schedule names, profiles, paths) are validated
before inclusion in crontab entries to prevent command injection.
"""

from __future__ import annotations

import platform
import subprocess

from scripts.core.schedule_manager import ScanSchedule
from scripts.core.validation import (
    validate_schedule_name,
    validate_profile,
    validate_cron_expression,
    validate_path_safe,
    validate_url,
    validate_container_image,
    validate_positive_int,
)


class UnsupportedPlatformError(Exception):
    """Platform does not support local cron."""

    pass


class CronNotAvailableError(Exception):
    """Cron is not available on this system."""

    pass


class CronInstallError(Exception):
    """Failed to install cron entry."""

    pass


class CronValidationError(Exception):
    """Invalid input detected during cron entry generation.

    Security: This exception is raised when user inputs fail validation,
    preventing potential command injection attacks.
    """

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
            CronValidationError: If schedule contains invalid input

        Example:
            >>> installer = CronInstaller()
            >>> installer.install(schedule)
            True
        """
        # Security: Validate schedule name before use in crontab
        schedule_name = schedule.metadata.name
        if not validate_schedule_name(schedule_name):
            raise CronValidationError(
                f"Invalid schedule name: '{schedule_name}'. "
                f"Schedule names must be alphanumeric with hyphens/underscores."
            )

        # Get current crontab
        current = self._get_crontab()

        # Remove any existing entries for this schedule
        current = self._remove_schedule_entries(current, schedule_name)

        # Generate and append new entry (includes additional validation)
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
            CronValidationError: If schedule name is invalid

        Example:
            >>> installer = CronInstaller()
            >>> installer.uninstall("nightly-deep")
            True
        """
        # Security: Validate schedule name before use in crontab matching
        if not validate_schedule_name(schedule_name):
            raise CronValidationError(
                f"Invalid schedule name: '{schedule_name}'. "
                f"Schedule names must be alphanumeric with hyphens/underscores."
            )

        current = self._get_crontab()
        filtered = self._remove_schedule_entries(current, schedule_name)

        if len(filtered) == len(current):
            return False  # Not found

        return self._set_crontab(filtered)

    def list_installed(self) -> list[str]:
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

    def _get_crontab(self) -> list[str]:
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

    def _set_crontab(self, lines: list[str]) -> bool:
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
        self, lines: list[str], schedule_name: str
    ) -> list[str]:
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

        Raises:
            CronValidationError: If any input fails validation

        Security:
            All user inputs are validated before inclusion in the cron command
            to prevent command injection attacks.
        """
        spec = schedule.spec.jobTemplate

        # Security: Validate cron schedule expression
        cron_schedule = schedule.spec.schedule
        if not validate_cron_expression(cron_schedule):
            raise CronValidationError(
                f"Invalid cron expression: '{cron_schedule}'. "
                f"Expected 5-field cron format (e.g., '0 2 * * *')."
            )

        # Security: Validate profile name
        if not validate_profile(spec.profile):
            raise CronValidationError(
                f"Invalid profile: '{spec.profile}'. "
                f"Valid profiles: fast, slim, balanced, deep."
            )

        # Build jmo command with validated inputs
        jmo_cmd = f"jmo scan --profile {spec.profile}"

        # Add targets with validation
        targets = spec.targets

        # 1. Repositories
        if "repositories" in targets:
            repos = targets["repositories"]
            if "repo" in repos:
                repo_path = repos["repo"]
                if not validate_path_safe(repo_path, "repo"):
                    raise CronValidationError(f"Invalid repo path: '{repo_path}'")
                jmo_cmd += f" --repo {repo_path}"
            if "repos_dir" in repos:
                repos_dir = repos["repos_dir"]
                if not validate_path_safe(repos_dir, "repos_dir"):
                    raise CronValidationError(f"Invalid repos_dir path: '{repos_dir}'")
                jmo_cmd += f" --repos-dir {repos_dir}"

        # 2. Container Images
        if "images" in targets:
            for image in targets["images"]:
                if not validate_container_image(image):
                    raise CronValidationError(f"Invalid container image: '{image}'")
                jmo_cmd += f" --image {image}"

        # 3. IaC Files
        if "iac" in targets:
            iac = targets["iac"]
            if "terraform_state" in iac:
                tf_path = iac["terraform_state"]
                if not validate_path_safe(tf_path, "terraform_state"):
                    raise CronValidationError(f"Invalid terraform_state path: '{tf_path}'")
                jmo_cmd += f" --terraform-state {tf_path}"
            if "cloudformation" in iac:
                cf_path = iac["cloudformation"]
                if not validate_path_safe(cf_path, "cloudformation"):
                    raise CronValidationError(f"Invalid cloudformation path: '{cf_path}'")
                jmo_cmd += f" --cloudformation {cf_path}"
            if "k8s_manifest" in iac:
                k8s_path = iac["k8s_manifest"]
                if not validate_path_safe(k8s_path, "k8s_manifest"):
                    raise CronValidationError(f"Invalid k8s_manifest path: '{k8s_path}'")
                jmo_cmd += f" --k8s-manifest {k8s_path}"

        # 4. Web URLs
        if "web" in targets:
            web = targets["web"]
            if "urls" in web:
                for url in web["urls"]:
                    if not validate_url(url):
                        raise CronValidationError(f"Invalid URL: '{url}'")
                    jmo_cmd += f" --url {url}"
            if "api_spec" in web:
                api_path = web["api_spec"]
                if not validate_path_safe(api_path, "api_spec"):
                    raise CronValidationError(f"Invalid api_spec path: '{api_path}'")
                jmo_cmd += f" --api-spec {api_path}"

        # 5. GitLab Repos (requires token from environment)
        if "gitlab" in targets:
            gitlab = targets["gitlab"]
            if "repo" in gitlab:
                gitlab_repo = gitlab["repo"]
                # GitLab repo format: group/project - validate no injection
                if not validate_path_safe(gitlab_repo, "gitlab_repo"):
                    raise CronValidationError(f"Invalid GitLab repo: '{gitlab_repo}'")
                jmo_cmd += f" --gitlab-repo {gitlab_repo}"
            if "group" in gitlab:
                gitlab_group = gitlab["group"]
                if not validate_schedule_name(gitlab_group):
                    raise CronValidationError(f"Invalid GitLab group: '{gitlab_group}'")
                jmo_cmd += f" --gitlab-group {gitlab_group}"
            # Token expected in environment variable GITLAB_TOKEN

        # 6. Kubernetes Clusters (requires kubectl config)
        if "kubernetes" in targets:
            k8s = targets["kubernetes"]
            if "context" in k8s:
                k8s_context = k8s["context"]
                if not validate_schedule_name(k8s_context):
                    raise CronValidationError(f"Invalid K8s context: '{k8s_context}'")
                jmo_cmd += f" --k8s-context {k8s_context}"
            if "namespace" in k8s:
                k8s_ns = k8s["namespace"]
                if not validate_schedule_name(k8s_ns):
                    raise CronValidationError(f"Invalid K8s namespace: '{k8s_ns}'")
                jmo_cmd += f" --k8s-namespace {k8s_ns}"
            elif k8s.get("all_namespaces"):
                jmo_cmd += " --k8s-all-namespaces"

        # Add results dir with date expansion
        results_base = spec.results.get("base_dir", "~/jmo-results")
        if not validate_path_safe(results_base, "results_base"):
            raise CronValidationError(f"Invalid results base path: '{results_base}'")
        jmo_cmd += f" --results-dir {results_base}/$(date +%Y-%m-%d)"

        # Add options with validation
        opts = spec.options
        if opts.get("allow_missing_tools"):
            jmo_cmd += " --allow-missing-tools"
        if "threads" in opts:
            threads = opts["threads"]
            if not validate_positive_int(threads, "threads", max_value=64):
                raise CronValidationError(f"Invalid threads value: '{threads}'")
            jmo_cmd += f" --threads {threads}"
        if "fail_on" in opts:
            fail_on = opts["fail_on"]
            valid_severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if fail_on.upper() not in valid_severities:
                raise CronValidationError(
                    f"Invalid fail_on value: '{fail_on}'. "
                    f"Valid: {', '.join(valid_severities)}"
                )
            jmo_cmd += f" --fail-on {fail_on}"

        # Multi-line entry with markers
        entry = f"""
{self.MARKER_START}{schedule.metadata.name}
{cron_schedule} {jmo_cmd}
{self.MARKER_END}
""".strip()

        return entry
