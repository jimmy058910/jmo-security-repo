"""Tests for scripts.cli.wizard_flows.config_models module.

Covers TargetConfig and WizardConfig defaults, serialization, and db_path logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.cli.wizard_flows.config_models import TargetConfig, WizardConfig


class TestTargetConfig:
    """Tests for TargetConfig defaults and serialization."""

    def test_default_type(self) -> None:
        tc = TargetConfig()
        assert tc.type == "repo"

    def test_default_strings_empty(self) -> None:
        tc = TargetConfig()
        assert tc.repo_mode == ""
        assert tc.repo_path == ""
        assert tc.image_name == ""
        assert tc.url == ""
        assert tc.gitlab_token == ""

    def test_default_tsv_dest(self) -> None:
        tc = TargetConfig()
        assert tc.tsv_dest == "repos-tsv"

    def test_default_gitlab_url(self) -> None:
        tc = TargetConfig()
        assert tc.gitlab_url == "https://gitlab.com"

    def test_default_k8s_all_namespaces(self) -> None:
        tc = TargetConfig()
        assert tc.k8s_all_namespaces is False

    def test_to_dict_returns_all_keys(self) -> None:
        tc = TargetConfig()
        d = tc.to_dict()
        expected_keys = {
            "type",
            "repo_mode",
            "repo_path",
            "tsv_path",
            "tsv_dest",
            "image_name",
            "images_file",
            "iac_type",
            "iac_path",
            "url",
            "urls_file",
            "api_spec",
            "gitlab_url",
            "gitlab_token",
            "gitlab_repo",
            "gitlab_group",
            "k8s_context",
            "k8s_namespace",
            "k8s_all_namespaces",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_redacts_token(self) -> None:
        tc = TargetConfig()
        tc.gitlab_token = "glpat-supersecret"
        d = tc.to_dict()
        assert d["gitlab_token"] == "***"

    def test_to_dict_empty_token_not_redacted(self) -> None:
        tc = TargetConfig()
        d = tc.to_dict()
        assert d["gitlab_token"] == ""

    def test_set_and_read_fields(self) -> None:
        tc = TargetConfig()
        tc.type = "image"
        tc.image_name = "nginx:latest"
        assert tc.type == "image"
        assert tc.image_name == "nginx:latest"


class TestWizardConfig:
    """Tests for WizardConfig defaults, db_path, and serialization."""

    def test_default_profile(self) -> None:
        wc = WizardConfig()
        assert wc.profile == "balanced"

    def test_default_use_docker(self) -> None:
        wc = WizardConfig()
        assert wc.use_docker is False

    def test_default_results_dir(self) -> None:
        wc = WizardConfig()
        assert wc.results_dir == "results"

    def test_default_threads_none(self) -> None:
        wc = WizardConfig()
        assert wc.threads is None

    def test_default_timeout_none(self) -> None:
        wc = WizardConfig()
        assert wc.timeout is None

    def test_default_fail_on_empty(self) -> None:
        wc = WizardConfig()
        assert wc.fail_on == ""

    def test_default_allow_missing_tools(self) -> None:
        wc = WizardConfig()
        assert wc.allow_missing_tools is True

    def test_default_human_logs(self) -> None:
        wc = WizardConfig()
        assert wc.human_logs is True

    def test_default_trend_flags(self) -> None:
        wc = WizardConfig()
        assert wc.analyze_trends is False
        assert wc.export_trends_html is False
        assert wc.export_trends_json is False

    def test_default_policies_enabled(self) -> None:
        wc = WizardConfig()
        assert wc.policies_enabled is False

    def test_target_is_target_config(self) -> None:
        wc = WizardConfig()
        assert isinstance(wc.target, TargetConfig)

    def test_to_dict_returns_all_keys(self) -> None:
        wc = WizardConfig()
        d = wc.to_dict()
        expected_keys = {
            "profile",
            "use_docker",
            "target",
            "results_dir",
            "threads",
            "timeout",
            "fail_on",
            "allow_missing_tools",
            "human_logs",
            "analyze_trends",
            "export_trends_html",
            "export_trends_json",
            "policies_enabled",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_target_is_dict(self) -> None:
        wc = WizardConfig()
        d = wc.to_dict()
        assert isinstance(d["target"], dict)

    def test_set_db_path_and_get(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Reset class-level state
        WizardConfig.set_db_path(None)
        try:
            WizardConfig.set_db_path("/tmp/custom.db")
            path = WizardConfig.get_db_path()
            assert path == Path("/tmp/custom.db").resolve()
        finally:
            WizardConfig.set_db_path(None)

    def test_get_db_path_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Default db path should be under home directory."""
        WizardConfig.set_db_path(None)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        path = WizardConfig.get_db_path()
        assert path == tmp_path / ".jmo" / "history.db"

    def test_set_db_path_none_resets(self) -> None:
        WizardConfig.set_db_path("/some/path.db")
        WizardConfig.set_db_path(None)
        assert WizardConfig._custom_db_path is None

    def test_to_dict_preserves_values(self) -> None:
        wc = WizardConfig()
        wc.profile = "deep"
        wc.threads = 8
        wc.fail_on = "HIGH"
        d = wc.to_dict()
        assert d["profile"] == "deep"
        assert d["threads"] == 8
        assert d["fail_on"] == "HIGH"
