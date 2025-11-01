"""Additional unit tests for cron_installer.py to reach 75%+ coverage.

These tests focus on missing coverage areas:
- uninstall() when schedule not found (returns False)
- _get_crontab() when crontab is empty
- _generate_cron_entry() with all 6 target types:
  * Container images
  * IaC files (terraform, cloudformation, k8s-manifest)
  * Web URLs and API specs
  * GitLab repositories
  * Kubernetes clusters
- _generate_cron_entry() with all options (allow_missing_tools, threads, fail_on)
"""

from unittest.mock import patch, MagicMock
import pytest

from scripts.core.cron_installer import CronInstaller
from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    BackendConfig,
    JobTemplateSpec,
)


@pytest.fixture
def basic_schedule():
    """Create minimal schedule for testing."""
    return ScanSchedule(
        metadata=ScheduleMetadata(
            name="test",
            labels={},
            annotations={},
            creationTimestamp="2025-10-31T00:00:00Z",
        ),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            timezone="UTC",
            suspend=False,
            backend=BackendConfig(type="local-cron"),
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={},
                options={},
                results={},
                notifications={"enabled": False},
            ),
        ),
        status={},
    )


# ========== Category 1: uninstall() Not Found ==========


def test_uninstall_schedule_not_found():
    """Test uninstall returns False when schedule not found in crontab."""
    with patch("subprocess.run") as mock_run:
        # Mock crontab -l with NO JMo schedules
        existing_crontab = """# Other user cron job
0 1 * * * /usr/bin/backup.sh
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=existing_crontab)

        installer = CronInstaller()
        result = installer.uninstall("nonexistent-schedule")

        # Should return False (not found)
        assert result is False

        # crontab - should NOT be called (no changes to write)
        assert mock_run.call_count == 1  # Only crontab -l


# ========== Category 2: _get_crontab() Empty ==========


def test_get_crontab_empty():
    """Test _get_crontab returns empty list when crontab is empty."""
    with patch("subprocess.run") as mock_run:
        # Mock crontab -l with empty output
        mock_run.return_value = MagicMock(returncode=0, stdout="")

        installer = CronInstaller()
        result = installer._get_crontab()

        assert result == []


def test_get_crontab_whitespace_only():
    """Test _get_crontab handles whitespace-only crontab."""
    with patch("subprocess.run") as mock_run:
        # Mock crontab -l with whitespace
        mock_run.return_value = MagicMock(returncode=0, stdout="  \n  \n  ")

        installer = CronInstaller()
        result = installer._get_crontab()

        assert result == []


# ========== Category 3: _generate_cron_entry() - Container Images ==========


def test_generate_cron_entry_with_images(basic_schedule):
    """Test _generate_cron_entry with container image targets."""
    basic_schedule.spec.jobTemplate.targets = {
        "images": ["nginx:latest", "postgres:14"]
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "# JMo Security Schedule: test" in entry
    assert "0 2 * * *" in entry
    assert "--image nginx:latest" in entry
    assert "--image postgres:14" in entry
    assert "# End JMo Schedule" in entry


# ========== Category 4: _generate_cron_entry() - IaC Files ==========


def test_generate_cron_entry_with_terraform(basic_schedule):
    """Test _generate_cron_entry with Terraform IaC target."""
    basic_schedule.spec.jobTemplate.targets = {
        "iac": {"terraform_state": "infrastructure.tfstate"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--terraform-state infrastructure.tfstate" in entry


def test_generate_cron_entry_with_cloudformation(basic_schedule):
    """Test _generate_cron_entry with CloudFormation IaC target."""
    basic_schedule.spec.jobTemplate.targets = {
        "iac": {"cloudformation": "template.yaml"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--cloudformation template.yaml" in entry


def test_generate_cron_entry_with_k8s_manifest(basic_schedule):
    """Test _generate_cron_entry with Kubernetes manifest IaC target."""
    basic_schedule.spec.jobTemplate.targets = {
        "iac": {"k8s_manifest": "deployment.yaml"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--k8s-manifest deployment.yaml" in entry


def test_generate_cron_entry_with_all_iac_types(basic_schedule):
    """Test _generate_cron_entry with all IaC types."""
    basic_schedule.spec.jobTemplate.targets = {
        "iac": {
            "terraform_state": "infra.tfstate",
            "cloudformation": "template.yaml",
            "k8s_manifest": "deployment.yaml",
        }
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--terraform-state infra.tfstate" in entry
    assert "--cloudformation template.yaml" in entry
    assert "--k8s-manifest deployment.yaml" in entry


# ========== Category 5: _generate_cron_entry() - Web URLs ==========


def test_generate_cron_entry_with_web_urls(basic_schedule):
    """Test _generate_cron_entry with web URL targets."""
    basic_schedule.spec.jobTemplate.targets = {
        "web": {"urls": ["https://example.com", "https://api.example.com"]}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--url https://example.com" in entry
    assert "--url https://api.example.com" in entry


def test_generate_cron_entry_with_api_spec(basic_schedule):
    """Test _generate_cron_entry with API spec target."""
    basic_schedule.spec.jobTemplate.targets = {"web": {"api_spec": "openapi.yaml"}}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--api-spec openapi.yaml" in entry


def test_generate_cron_entry_with_web_urls_and_api_spec(basic_schedule):
    """Test _generate_cron_entry with both URLs and API spec."""
    basic_schedule.spec.jobTemplate.targets = {
        "web": {"urls": ["https://example.com"], "api_spec": "openapi.yaml"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--url https://example.com" in entry
    assert "--api-spec openapi.yaml" in entry


# ========== Category 6: _generate_cron_entry() - GitLab Repos ==========


def test_generate_cron_entry_with_gitlab_repo(basic_schedule):
    """Test _generate_cron_entry with GitLab repository target."""
    basic_schedule.spec.jobTemplate.targets = {"gitlab": {"repo": "mygroup/myrepo"}}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--gitlab-repo mygroup/myrepo" in entry


def test_generate_cron_entry_with_gitlab_group(basic_schedule):
    """Test _generate_cron_entry with GitLab group target."""
    basic_schedule.spec.jobTemplate.targets = {"gitlab": {"group": "mygroup"}}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--gitlab-group mygroup" in entry


def test_generate_cron_entry_with_gitlab_repo_and_group(basic_schedule):
    """Test _generate_cron_entry with both GitLab repo and group."""
    basic_schedule.spec.jobTemplate.targets = {
        "gitlab": {"repo": "mygroup/myrepo", "group": "anothergroup"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--gitlab-repo mygroup/myrepo" in entry
    assert "--gitlab-group anothergroup" in entry


# ========== Category 7: _generate_cron_entry() - Kubernetes Clusters ==========


def test_generate_cron_entry_with_k8s_context(basic_schedule):
    """Test _generate_cron_entry with Kubernetes context target."""
    basic_schedule.spec.jobTemplate.targets = {"kubernetes": {"context": "prod"}}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--k8s-context prod" in entry


def test_generate_cron_entry_with_k8s_namespace(basic_schedule):
    """Test _generate_cron_entry with Kubernetes namespace."""
    basic_schedule.spec.jobTemplate.targets = {
        "kubernetes": {"context": "prod", "namespace": "default"}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--k8s-context prod" in entry
    assert "--k8s-namespace default" in entry


def test_generate_cron_entry_with_k8s_all_namespaces(basic_schedule):
    """Test _generate_cron_entry with all_namespaces flag."""
    basic_schedule.spec.jobTemplate.targets = {
        "kubernetes": {"context": "prod", "all_namespaces": True}
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--k8s-context prod" in entry
    assert "--k8s-all-namespaces" in entry
    assert "--k8s-namespace" not in entry  # Should NOT include namespace


# ========== Category 8: _generate_cron_entry() - Options ==========


def test_generate_cron_entry_with_allow_missing_tools(basic_schedule):
    """Test _generate_cron_entry with allow_missing_tools option."""
    basic_schedule.spec.jobTemplate.options = {"allow_missing_tools": True}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--allow-missing-tools" in entry


def test_generate_cron_entry_with_threads_option(basic_schedule):
    """Test _generate_cron_entry with threads option."""
    basic_schedule.spec.jobTemplate.options = {"threads": 8}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--threads 8" in entry


def test_generate_cron_entry_with_fail_on_option(basic_schedule):
    """Test _generate_cron_entry with fail_on option."""
    basic_schedule.spec.jobTemplate.options = {"fail_on": "HIGH"}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--fail-on HIGH" in entry


def test_generate_cron_entry_with_all_options(basic_schedule):
    """Test _generate_cron_entry with all options."""
    basic_schedule.spec.jobTemplate.options = {
        "allow_missing_tools": True,
        "threads": 4,
        "fail_on": "CRITICAL",
    }

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--allow-missing-tools" in entry
    assert "--threads 4" in entry
    assert "--fail-on CRITICAL" in entry


# ========== Category 9: _generate_cron_entry() - Custom Results Base Dir ==========


def test_generate_cron_entry_with_custom_results_dir(basic_schedule):
    """Test _generate_cron_entry with custom results base directory."""
    basic_schedule.spec.jobTemplate.results = {"base_dir": "/var/jmo-scans"}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--results-dir /var/jmo-scans/$(date +%Y-%m-%d)" in entry


def test_generate_cron_entry_default_results_dir(basic_schedule):
    """Test _generate_cron_entry uses default results dir when not specified."""
    basic_schedule.spec.jobTemplate.results = {}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    assert "--results-dir ~/jmo-results/$(date +%Y-%m-%d)" in entry


# ========== Category 10: _generate_cron_entry() - Multi-Target Comprehensive ==========


def test_generate_cron_entry_comprehensive_all_targets(basic_schedule):
    """Test _generate_cron_entry with all target types in one schedule."""
    basic_schedule.spec.jobTemplate.profile = "deep"
    basic_schedule.spec.jobTemplate.targets = {
        "repositories": {"repos_dir": "~/repos"},
        "images": ["nginx:latest"],
        "iac": {"terraform_state": "infra.tfstate"},
        "web": {"urls": ["https://example.com"]},
        "gitlab": {"repo": "mygroup/myrepo"},
        "kubernetes": {"context": "prod", "namespace": "default"},
    }
    basic_schedule.spec.jobTemplate.options = {
        "allow_missing_tools": True,
        "threads": 2,
        "fail_on": "HIGH",
    }
    basic_schedule.spec.jobTemplate.results = {"base_dir": "/var/scans"}

    installer = CronInstaller()
    entry = installer._generate_cron_entry(basic_schedule)

    # Verify profile
    assert "jmo scan --profile deep" in entry

    # Verify all targets
    assert "--repos-dir ~/repos" in entry
    assert "--image nginx:latest" in entry
    assert "--terraform-state infra.tfstate" in entry
    assert "--url https://example.com" in entry
    assert "--gitlab-repo mygroup/myrepo" in entry
    assert "--k8s-context prod" in entry
    assert "--k8s-namespace default" in entry

    # Verify options
    assert "--allow-missing-tools" in entry
    assert "--threads 2" in entry
    assert "--fail-on HIGH" in entry

    # Verify results dir
    assert "--results-dir /var/scans/$(date +%Y-%m-%d)" in entry

    # Verify cron schedule
    assert "0 2 * * *" in entry

    # Verify markers
    assert "# JMo Security Schedule: test" in entry
    assert "# End JMo Schedule" in entry
