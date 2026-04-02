"""
Tests for scripts/cli/scan_session.py - Scan session checkpointing.

Covers:
- ScanSession dataclass (creation, serialization, roundtrip, properties)
- ToolRecord and TargetRecord (creation, serialization)
- Atomic file I/O (create, overwrite, parent dir creation, cleanup on failure)
- Session load/save (valid, corrupt, missing, version mismatch)
- Config hash (deterministic, change detection, missing file)
- Session validation (all present, missing files, skip incomplete)
- Format summary (minutes, hours, days display)
"""

import json
import os
import time


from scripts.cli.scan_session import (
    ScanSession,
    TargetRecord,
    ToolRecord,
    SESSION_VERSION,
    compute_config_hash,
    delete_session,
    format_session_summary,
    load_session,
    save_session,
    validate_session_results,
    _atomic_write_json,
)

# ── ToolRecord ──────────────────────────────────────────────────


class TestToolRecord:
    def test_default_values(self):
        tr = ToolRecord(name="trivy")
        assert tr.name == "trivy"
        assert tr.status == "pending"
        assert tr.error == ""
        assert tr.output_file == ""

    def test_to_dict(self):
        tr = ToolRecord(
            name="semgrep",
            status="completed",
            error="",
            output_file="/out/semgrep.json",
        )
        d = tr.to_dict()
        assert d["name"] == "semgrep"
        assert d["status"] == "completed"

    def test_from_dict(self):
        d = {
            "name": "bandit",
            "status": "failed",
            "error": "timeout",
            "output_file": "",
        }
        tr = ToolRecord.from_dict(d)
        assert tr.name == "bandit"
        assert tr.status == "failed"
        assert tr.error == "timeout"

    def test_roundtrip(self):
        tr = ToolRecord(
            name="trivy", status="completed", error="", output_file="/path/to/out.json"
        )
        tr2 = ToolRecord.from_dict(tr.to_dict())
        assert tr2.name == tr.name
        assert tr2.status == tr.status
        assert tr2.output_file == tr.output_file


# ── TargetRecord ──────────────────────────────────────────────────


class TestTargetRecord:
    def test_default_values(self):
        tr = TargetRecord(target_type="repo", target_id="myrepo")
        assert tr.target_type == "repo"
        assert tr.target_id == "myrepo"
        assert tr.completed is False
        assert tr.tools == {}

    def test_with_tools(self):
        tools = {"trivy": ToolRecord(name="trivy", status="completed")}
        tr = TargetRecord(
            target_type="image", target_id="nginx:latest", completed=True, tools=tools
        )
        assert tr.completed is True
        assert "trivy" in tr.tools

    def test_roundtrip(self):
        tools = {
            "trivy": ToolRecord(name="trivy", status="completed"),
            "semgrep": ToolRecord(name="semgrep", status="failed", error="crash"),
        }
        tr = TargetRecord(
            target_type="repo", target_id="myrepo", completed=True, tools=tools
        )
        tr2 = TargetRecord.from_dict(tr.to_dict())
        assert tr2.target_type == "repo"
        assert tr2.completed is True
        assert tr2.tools["trivy"].status == "completed"
        assert tr2.tools["semgrep"].error == "crash"


# ── ScanSession ──────────────────────────────────────────────────


class TestScanSession:
    def test_creation(self):
        session = ScanSession(
            session_id="test-123",
            profile="balanced",
            config_hash="abc123",
            started_at=time.time(),
            pid=os.getpid(),
        )
        assert session.session_id == "test-123"
        assert session.profile == "balanced"
        assert session.total_targets == 0
        assert session.completed_count == 0
        assert session.version == SESSION_VERSION

    def test_register_target(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy", "semgrep"])
        assert session.total_targets == 1
        assert "myrepo" in session.targets
        assert "trivy" in session.targets["myrepo"].tools
        assert "semgrep" in session.targets["myrepo"].tools

    def test_mark_target_complete(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy", "semgrep"])
        session.mark_target_complete("myrepo", {"trivy": True, "semgrep": False})
        assert session.targets["myrepo"].completed is True
        assert session.targets["myrepo"].tools["trivy"].status == "completed"
        assert session.targets["myrepo"].tools["semgrep"].status == "failed"

    def test_mark_target_complete_skips_metadata_keys(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        session.mark_target_complete(
            "myrepo", {"trivy": True, "__attempts__": {"trivy": 2}}
        )
        assert session.targets["myrepo"].completed is True
        # __attempts__ should not crash or create a tool record

    def test_mark_nonexistent_target(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        # Should not raise
        session.mark_target_complete("nonexistent", {"trivy": True})

    def test_completed_and_pending_targets(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "repo1", ["trivy"])
        session.register_target("repo", "repo2", ["trivy"])
        session.register_target("repo", "repo3", ["trivy"])

        session.mark_target_complete("repo1", {"trivy": True})
        session.mark_target_complete("repo3", {"trivy": True})

        assert session.completed_count == 2
        assert "repo2" in session.pending_targets
        assert "repo1" in session.completed_targets
        assert "repo3" in session.completed_targets

    def test_is_target_completed(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "repo1", ["trivy"])
        assert session.is_target_completed("repo1") is False
        session.mark_target_complete("repo1", {"trivy": True})
        assert session.is_target_completed("repo1") is True
        assert session.is_target_completed("nonexistent") is False

    def test_roundtrip_serialization(self):
        session = ScanSession(
            session_id="test-456",
            profile="deep",
            config_hash="deadbeef",
            started_at=1234567890.0,
            pid=42,
        )
        session.register_target("repo", "repo1", ["trivy", "semgrep"])
        session.register_target("image", "nginx:latest", ["trivy"])
        session.mark_target_complete("repo1", {"trivy": True, "semgrep": False})

        data = session.to_dict()
        session2 = ScanSession.from_dict(data)

        assert session2.session_id == "test-456"
        assert session2.profile == "deep"
        assert session2.config_hash == "deadbeef"
        assert session2.started_at == 1234567890.0
        assert session2.pid == 42
        assert session2.total_targets == 2
        assert session2.completed_count == 1
        assert session2.targets["repo1"].tools["trivy"].status == "completed"
        assert session2.targets["repo1"].tools["semgrep"].status == "failed"


# ── Atomic Write ──────────────────────────────────────────────────


class TestAtomicWrite:
    def test_create_new_file(self, tmp_path):
        path = tmp_path / "test.json"
        _atomic_write_json(path, {"key": "value"})
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == {"key": "value"}

    def test_overwrite_existing(self, tmp_path):
        path = tmp_path / "test.json"
        _atomic_write_json(path, {"version": 1})
        _atomic_write_json(path, {"version": 2})
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == 2

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "subdir" / "deep" / "test.json"
        _atomic_write_json(path, {"nested": True})
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["nested"] is True


# ── Load/Save Session ──────────────────────────────────────────────


class TestLoadSaveSession:
    def test_save_and_load(self, tmp_path):
        session_path = tmp_path / "session.json"
        session = ScanSession(
            session_id="roundtrip",
            profile="balanced",
            config_hash="abc",
            started_at=time.time(),
            pid=os.getpid(),
        )
        session.register_target("repo", "myrepo", ["trivy"])
        save_session(session, session_path)
        assert session_path.exists()

        loaded = load_session(session_path)
        assert loaded is not None
        assert loaded.session_id == "roundtrip"
        assert loaded.total_targets == 1

    def test_load_missing_file(self, tmp_path):
        result = load_session(tmp_path / "missing.json")
        assert result is None

    def test_load_corrupt_json(self, tmp_path):
        session_path = tmp_path / "session.json"
        session_path.write_text("not json {{{", encoding="utf-8")
        result = load_session(session_path)
        assert result is None

    def test_load_non_dict_json(self, tmp_path):
        session_path = tmp_path / "session.json"
        session_path.write_text("[1, 2, 3]", encoding="utf-8")
        result = load_session(session_path)
        assert result is None

    def test_load_version_mismatch(self, tmp_path):
        session_path = tmp_path / "session.json"
        data = {
            "version": 999,
            "session_id": "old",
            "config_hash": "abc",
            "started_at": 0.0,
            "pid": 1,
        }
        session_path.write_text(json.dumps(data), encoding="utf-8")
        result = load_session(session_path)
        assert result is None

    def test_load_valid_version(self, tmp_path):
        session_path = tmp_path / "session.json"
        data = {
            "version": SESSION_VERSION,
            "session_id": "current",
            "config_hash": "abc",
            "started_at": 0.0,
            "pid": 1,
            "targets": {},
        }
        session_path.write_text(json.dumps(data), encoding="utf-8")
        result = load_session(session_path)
        assert result is not None
        assert result.session_id == "current"


# ── Delete Session ──────────────────────────────────────────────


class TestDeleteSession:
    def test_delete_existing(self, tmp_path):
        session_path = tmp_path / "session.json"
        session_path.write_text("{}", encoding="utf-8")
        delete_session(session_path)
        assert not session_path.exists()

    def test_delete_missing(self, tmp_path):
        # Should not raise
        delete_session(tmp_path / "missing.json")


# ── Config Hash ──────────────────────────────────────────────


class TestConfigHash:
    def test_deterministic(self, tmp_path):
        config = tmp_path / "jmo.yml"
        config.write_text("default_profile: fast\n", encoding="utf-8")
        h1 = compute_config_hash(config)
        h2 = compute_config_hash(config)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_change_detection(self, tmp_path):
        config = tmp_path / "jmo.yml"
        config.write_text("default_profile: fast\n", encoding="utf-8")
        h1 = compute_config_hash(config)
        config.write_text("default_profile: deep\n", encoding="utf-8")
        h2 = compute_config_hash(config)
        assert h1 != h2

    def test_missing_file(self, tmp_path):
        result = compute_config_hash(tmp_path / "nonexistent.yml")
        assert result == ""

    def test_accepts_string_path(self, tmp_path):
        config = tmp_path / "jmo.yml"
        config.write_text("tools: [trivy]\n", encoding="utf-8")
        h = compute_config_hash(str(config))
        assert len(h) == 64


# ── Session Validation ──────────────────────────────────────────


class TestValidateSessionResults:
    def test_all_present(self, tmp_path):
        results_dir = tmp_path / "results"
        repo_dir = results_dir / "individual-repos"
        repo_dir.mkdir(parents=True)
        (repo_dir / "myrepo.json").write_text("{}", encoding="utf-8")

        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        session.mark_target_complete("myrepo", {"trivy": True})

        assert validate_session_results(session, results_dir) is True

    def test_missing_results_dir(self, tmp_path):
        results_dir = tmp_path / "results"
        # Don't create the directory

        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        session.mark_target_complete("myrepo", {"trivy": True})

        assert validate_session_results(session, results_dir) is False

    def test_no_output_files(self, tmp_path):
        results_dir = tmp_path / "results"
        repo_dir = results_dir / "individual-repos"
        repo_dir.mkdir(parents=True)
        # Don't create any JSON files

        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        session.mark_target_complete("myrepo", {"trivy": True})

        assert validate_session_results(session, results_dir) is False

    def test_skip_incomplete_targets(self, tmp_path):
        results_dir = tmp_path / "results"
        repo_dir = results_dir / "individual-repos"
        repo_dir.mkdir(parents=True)

        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        # Not marked complete - should be skipped in validation

        assert validate_session_results(session, results_dir) is True

    def test_empty_session(self, tmp_path):
        results_dir = tmp_path / "results"
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=0.0,
            pid=1,
        )
        assert validate_session_results(session, results_dir) is True


# ── Format Summary ──────────────────────────────────────────────


class TestFormatSummary:
    def test_seconds_ago(self):
        session = ScanSession(
            session_id="test",
            profile="fast",
            config_hash="hash",
            started_at=time.time() - 30,
            pid=1,
        )
        session.register_target("repo", "repo1", ["trivy"])
        summary = format_session_summary(session)
        assert "30s ago" in summary
        assert "0/1 targets" in summary
        assert "fast profile" in summary

    def test_minutes_ago(self):
        session = ScanSession(
            session_id="test",
            profile="balanced",
            config_hash="hash",
            started_at=time.time() - 2700,
            pid=1,  # 45 min
        )
        for i in range(29):
            session.register_target("repo", f"repo{i}", ["trivy"])
        for i in range(18):
            session.mark_target_complete(f"repo{i}", {"trivy": True})

        summary = format_session_summary(session)
        assert "45min ago" in summary
        assert "18/29 targets" in summary
        assert "balanced profile" in summary

    def test_hours_ago(self):
        session = ScanSession(
            session_id="test",
            profile="deep",
            config_hash="hash",
            started_at=time.time() - 7200,
            pid=1,  # 2 hours
        )
        summary = format_session_summary(session)
        assert "2.0h ago" in summary

    def test_days_ago(self):
        session = ScanSession(
            session_id="test",
            profile="deep",
            config_hash="hash",
            started_at=time.time() - 172800,
            pid=1,  # 2 days
        )
        summary = format_session_summary(session)
        assert "2.0d ago" in summary

    def test_custom_profile(self):
        session = ScanSession(
            session_id="test",
            profile="",
            config_hash="hash",
            started_at=time.time(),
            pid=1,
        )
        summary = format_session_summary(session)
        assert "custom profile" in summary


# ── Integration: End-to-End Session Lifecycle ────────────────────


class TestSessionLifecycle:
    def test_full_lifecycle(self, tmp_path):
        """Test: create session -> checkpoint targets -> save -> reload -> resume."""
        session_path = tmp_path / ".jmo" / "scan-session.json"

        # Create session
        session = ScanSession(
            session_id="lifecycle-test",
            profile="balanced",
            config_hash="abc123",
            started_at=time.time(),
            pid=os.getpid(),
        )
        session.register_target("repo", "repo1", ["trivy", "semgrep"])
        session.register_target("repo", "repo2", ["trivy", "semgrep"])
        session.register_target("image", "nginx:latest", ["trivy"])

        # Complete first target and checkpoint
        session.mark_target_complete("repo1", {"trivy": True, "semgrep": True})
        save_session(session, session_path)

        # Simulate crash: load from disk
        restored = load_session(session_path)
        assert restored is not None
        assert restored.completed_count == 1
        assert restored.is_target_completed("repo1") is True
        assert restored.is_target_completed("repo2") is False
        assert restored.is_target_completed("nginx:latest") is False

        # Complete remaining targets
        restored.mark_target_complete("repo2", {"trivy": True, "semgrep": False})
        restored.mark_target_complete("nginx:latest", {"trivy": True})
        save_session(restored, session_path)

        # Clean exit
        delete_session(session_path)
        assert not session_path.exists()

    def test_config_change_invalidates_session(self, tmp_path):
        """Test: config change between sessions causes session discard."""
        config = tmp_path / "jmo.yml"
        session_path = tmp_path / "session.json"

        # Session 1 with config v1
        config.write_text("tools: [trivy]\n", encoding="utf-8")
        hash1 = compute_config_hash(config)
        session = ScanSession(
            session_id="s1",
            profile="fast",
            config_hash=hash1,
            started_at=time.time(),
            pid=1,
        )
        session.register_target("repo", "myrepo", ["trivy"])
        session.mark_target_complete("myrepo", {"trivy": True})
        save_session(session, session_path)

        # Config changes
        config.write_text("tools: [trivy, semgrep]\n", encoding="utf-8")
        hash2 = compute_config_hash(config)

        # Load and check hash mismatch
        restored = load_session(session_path)
        assert restored is not None
        assert restored.config_hash != hash2  # Config changed
