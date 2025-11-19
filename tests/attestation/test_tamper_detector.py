"""
Tests for advanced tamper detection.

Tests the TamperDetector class which detects:
- Timestamp anomalies (future dates, impossible durations, stale attestations)
- Builder consistency violations (unauthorized CI platform changes)
- Tool version rollback attacks (defending against bypass)
- Suspicious patterns (path traversal, localhost builders, missing fields)
"""

import json
from unittest.mock import patch
from datetime import datetime, timezone
from scripts.core.attestation.tamper_detector import (
    TamperDetector,
    TamperIndicator,
    TamperSeverity,
    TamperIndicatorType,
)


class TestTamperDetectorInitialization:
    """Tests for TamperDetector initialization."""

    def test_init_default_parameters(self):
        """Test initialization with default parameters."""
        detector = TamperDetector()

        assert detector.max_age_days == 90
        assert detector.max_duration_hours == 24
        assert detector.allow_builder_version_change is True

    def test_init_custom_parameters(self):
        """Test initialization with custom parameters."""
        detector = TamperDetector(
            max_age_days=30,
            max_duration_hours=12,
            allow_builder_version_change=False,
        )

        assert detector.max_age_days == 30
        assert detector.max_duration_hours == 12
        assert detector.allow_builder_version_change is False


class TestTimestampAnomalies:
    """Tests for check_timestamp_anomalies method."""

    @patch("scripts.core.attestation.tamper_detector.datetime")
    def test_future_started_timestamp(self, mock_datetime, tmp_path):
        """Test detection of future startedOn timestamp."""
        detector = TamperDetector()

        # Mock current time
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        mock_datetime.fromisoformat = datetime.fromisoformat

        # Create attestation with future startedOn
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2025-01-15T13:00:00Z",  # 1 hour in future
                        "finishedOn": "2025-01-15T14:00:00Z",
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        assert len(indicators) >= 1
        future_indicators = [
            i for i in indicators if "started in the future" in i.description.lower()
        ]
        assert len(future_indicators) == 1
        assert future_indicators[0].severity == TamperSeverity.CRITICAL
        assert (
            future_indicators[0].indicator_type == TamperIndicatorType.TIMESTAMP_ANOMALY
        )

    @patch("scripts.core.attestation.tamper_detector.datetime")
    def test_future_finished_timestamp(self, mock_datetime, tmp_path):
        """Test detection of future finishedOn timestamp."""
        detector = TamperDetector()

        # Mock current time
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        mock_datetime.fromisoformat = datetime.fromisoformat

        # Create attestation with future finishedOn
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2025-01-15T11:00:00Z",
                        "finishedOn": "2025-01-15T13:00:00Z",  # 1 hour in future
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        assert len(indicators) >= 1
        future_indicators = [
            i for i in indicators if "finished in the future" in i.description.lower()
        ]
        assert len(future_indicators) == 1
        assert future_indicators[0].severity == TamperSeverity.CRITICAL

    def test_impossible_duration_finish_before_start(self, tmp_path):
        """Test detection of finish before start (impossible duration)."""
        detector = TamperDetector()

        # Create attestation where finish is before start
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2025-01-15T12:00:00Z",
                        "finishedOn": "2025-01-15T11:00:00Z",  # 1 hour before start
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        impossible_indicators = [
            i for i in indicators if "finished before it started" in i.description
        ]
        assert len(impossible_indicators) == 1
        assert impossible_indicators[0].severity == TamperSeverity.CRITICAL
        assert (
            impossible_indicators[0].indicator_type
            == TamperIndicatorType.TIMESTAMP_ANOMALY
        )

    def test_extremely_long_duration(self, tmp_path):
        """Test detection of extremely long build duration."""
        detector = TamperDetector(max_duration_hours=24)

        # Create attestation with 30-hour duration
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2025-01-15T00:00:00Z",
                        "finishedOn": "2025-01-16T06:00:00Z",  # 30 hours later
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        long_duration_indicators = [
            i for i in indicators if "duration exceeds" in i.description
        ]
        assert len(long_duration_indicators) == 1
        assert long_duration_indicators[0].severity == TamperSeverity.HIGH
        assert long_duration_indicators[0].evidence["duration_hours"] == 30

    @patch("scripts.core.attestation.tamper_detector.datetime")
    def test_very_old_attestation(self, mock_datetime, tmp_path):
        """Test detection of very old attestation (potential replay attack)."""
        detector = TamperDetector(max_age_days=90)

        # Mock current time
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        mock_datetime.fromisoformat = datetime.fromisoformat

        # Create attestation from 100 days ago
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2024-10-06T11:00:00Z",
                        "finishedOn": "2024-10-06T12:00:00Z",  # 100 days ago
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        old_indicators = [i for i in indicators if "days old" in i.description]
        assert len(old_indicators) == 1
        assert old_indicators[0].severity == TamperSeverity.MEDIUM
        assert old_indicators[0].evidence["age_days"] > 90

    def test_missing_timestamps(self, tmp_path):
        """Test detection of missing timestamp fields."""
        detector = TamperDetector()

        # Create attestation with missing timestamps
        attestation_data = {
            "predicate": {"runDetails": {"metadata": {}}}  # No timestamps
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        missing_indicators = [
            i for i in indicators if "Missing required timestamp" in i.description
        ]
        assert len(missing_indicators) == 1
        assert missing_indicators[0].severity == TamperSeverity.MEDIUM
        assert missing_indicators[0].indicator_type == TamperIndicatorType.MISSING_FIELD

    def test_invalid_timestamp_format(self, tmp_path):
        """Test handling of invalid timestamp format."""
        detector = TamperDetector()

        # Create attestation with invalid timestamp
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "invalid-timestamp",
                        "finishedOn": "2025-01-15T12:00:00Z",
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        # Should not crash, just log warning
        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        # Should still detect missing timestamp
        assert len(indicators) >= 0

    def test_valid_timestamps_no_anomalies(self, tmp_path):
        """Test that valid timestamps produce no anomalies."""
        detector = TamperDetector()

        # Create valid attestation
        attestation_data = {
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": "2025-01-15T11:00:00Z",
                        "finishedOn": "2025-01-15T12:00:00Z",
                    }
                }
            }
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_timestamp_anomalies(str(attestation_file))

        # Should have no critical/high indicators
        critical_or_high = [
            i
            for i in indicators
            if i.severity in [TamperSeverity.CRITICAL, TamperSeverity.HIGH]
        ]
        assert len(critical_or_high) == 0


class TestBuilderConsistency:
    """Tests for check_builder_consistency method."""

    def test_builder_id_change_critical(self, tmp_path):
        """Test detection of builder ID change (critical)."""
        detector = TamperDetector()

        # Create current attestation (GitLab)
        current_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://gitlab.com/myproject",
                        "version": {"jmo": "1.0.0"},
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Create historical attestation (GitHub)
        historical_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.0.0"},
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_builder_consistency(
            str(current_file), [str(historical_file)]
        )

        builder_change_indicators = [
            i for i in indicators if "Builder ID changed" in i.description
        ]
        assert len(builder_change_indicators) == 1
        assert builder_change_indicators[0].severity == TamperSeverity.CRITICAL
        assert (
            builder_change_indicators[0].indicator_type
            == TamperIndicatorType.BUILDER_INCONSISTENCY
        )

    def test_builder_version_change_disallowed(self, tmp_path):
        """Test builder version change when disallowed."""
        detector = TamperDetector(allow_builder_version_change=False)

        # Current attestation
        current_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.1.0"},
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation
        historical_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.0.0"},  # Different version
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_builder_consistency(
            str(current_file), [str(historical_file)]
        )

        version_change_indicators = [
            i for i in indicators if "Builder version changed" in i.description
        ]
        assert len(version_change_indicators) == 1
        assert version_change_indicators[0].severity == TamperSeverity.HIGH

    def test_builder_version_change_allowed(self, tmp_path):
        """Test builder version change when allowed."""
        detector = TamperDetector(allow_builder_version_change=True)

        # Current attestation
        current_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.1.0"},
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation
        historical_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.0.0"},  # Different version
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_builder_consistency(
            str(current_file), [str(historical_file)]
        )

        # Should not flag version change
        version_change_indicators = [
            i for i in indicators if "Builder version changed" in i.description
        ]
        assert len(version_change_indicators) == 0

    def test_missing_builder_id(self, tmp_path):
        """Test detection of missing builder ID."""
        detector = TamperDetector()

        # Create attestation with missing builder ID
        current_data = {"predicate": {"runDetails": {"builder": {}}}}  # No ID

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        indicators = detector.check_builder_consistency(str(current_file), [])

        missing_indicators = [
            i for i in indicators if "Missing builder ID" in i.description
        ]
        assert len(missing_indicators) == 1
        assert missing_indicators[0].severity == TamperSeverity.MEDIUM
        assert missing_indicators[0].indicator_type == TamperIndicatorType.MISSING_FIELD

    def test_no_historical_attestations(self, tmp_path):
        """Test with no historical attestations (no comparison)."""
        detector = TamperDetector()

        # Current attestation
        current_data = {
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/myproject",
                        "version": {"jmo": "1.0.0"},
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        indicators = detector.check_builder_consistency(str(current_file), [])

        # Should have no indicators (nothing to compare against)
        assert len(indicators) == 0


class TestToolRollback:
    """Tests for check_tool_rollback method."""

    def test_critical_tool_downgrade(self, tmp_path):
        """Test detection of critical tool downgrade (trivy)."""
        detector = TamperDetector()

        # Current attestation (trivy 0.30.0)
        current_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "trivy", "version": "0.30.0"},
                        ]
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation (trivy 0.50.0)
        historical_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "trivy", "version": "0.50.0"},
                        ]
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_tool_rollback(
            str(current_file), [str(historical_file)]
        )

        rollback_indicators = [
            i for i in indicators if "downgraded" in i.description.lower()
        ]
        assert len(rollback_indicators) == 1
        assert rollback_indicators[0].severity == TamperSeverity.CRITICAL
        assert (
            rollback_indicators[0].indicator_type == TamperIndicatorType.TOOL_ROLLBACK
        )
        assert "trivy" in rollback_indicators[0].description

    def test_non_critical_tool_downgrade(self, tmp_path):
        """Test detection of non-critical tool downgrade."""
        detector = TamperDetector()

        # Current attestation (hadolint 2.10.0)
        current_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "hadolint", "version": "2.10.0"},
                        ]
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation (hadolint 2.12.0)
        historical_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "hadolint", "version": "2.12.0"},
                        ]
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_tool_rollback(
            str(current_file), [str(historical_file)]
        )

        rollback_indicators = [
            i for i in indicators if "downgraded" in i.description.lower()
        ]
        assert len(rollback_indicators) == 1
        assert rollback_indicators[0].severity == TamperSeverity.HIGH

    def test_tool_upgrade_no_indicator(self, tmp_path):
        """Test that tool upgrades do not trigger indicators."""
        detector = TamperDetector()

        # Current attestation (trivy 0.55.0)
        current_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "trivy", "version": "0.55.0"},
                        ]
                    }
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation (trivy 0.50.0)
        historical_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": [
                            {"name": "trivy", "version": "0.50.0"},
                        ]
                    }
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_tool_rollback(
            str(current_file), [str(historical_file)]
        )

        # Should have no indicators (upgrade is fine)
        assert len(indicators) == 0

    def test_resolved_dependencies_format(self, tmp_path):
        """Test fallback to resolvedDependencies format."""
        detector = TamperDetector()

        # Current attestation (using resolvedDependencies instead of externalParameters)
        current_data = {
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.30.0"},
                    ]
                }
            }
        }

        current_file = tmp_path / "current.json"
        current_file.write_text(json.dumps(current_data))

        # Historical attestation
        historical_data = {
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.50.0"},
                    ]
                }
            }
        }

        historical_file = tmp_path / "historical.json"
        historical_file.write_text(json.dumps(historical_data))

        indicators = detector.check_tool_rollback(
            str(current_file), [str(historical_file)]
        )

        # Should still detect downgrade
        rollback_indicators = [
            i for i in indicators if "downgraded" in i.description.lower()
        ]
        assert len(rollback_indicators) == 1


class TestSuspiciousPatterns:
    """Tests for check_suspicious_patterns method."""

    def test_empty_findings_with_many_tools(self, tmp_path):
        """Test detection of zero findings with many tools (scan bypass)."""
        detector = TamperDetector()

        # Create subject file with zero findings
        subject_data = {"findings": []}
        subject_file = tmp_path / "findings.json"
        subject_file.write_text(json.dumps(subject_data))

        # Create attestation with 5+ tools
        attestation_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": ["trivy", "semgrep", "trufflehog", "syft", "checkov"],
                        "profile": "balanced",
                    }
                },
                "runDetails": {"builder": {"id": "https://github.com/test/repo"}},
            },
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc"}}],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        empty_findings_indicators = [
            i for i in indicators if "Zero findings" in i.description
        ]
        assert len(empty_findings_indicators) == 1
        assert empty_findings_indicators[0].severity == TamperSeverity.HIGH
        assert (
            empty_findings_indicators[0].indicator_type
            == TamperIndicatorType.SUSPICIOUS_PATTERN
        )

    def test_path_traversal_in_subject_name(self, tmp_path):
        """Test detection of path traversal in subject name."""
        detector = TamperDetector()

        # Create attestation with suspicious subject name
        attestation_data = {
            "predicate": {
                "buildDefinition": {"externalParameters": {"tools": []}},
                "runDetails": {"builder": {"id": "https://github.com/test/repo"}},
            },
            "subject": [
                {
                    "name": "../../etc/passwd",  # Path traversal
                    "digest": {"sha256": "abc"},
                }
            ],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        subject_file = tmp_path / "findings.json"
        subject_file.write_text("{}")

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        path_traversal_indicators = [
            i for i in indicators if "Suspicious subject name" in i.description
        ]
        assert len(path_traversal_indicators) == 1
        assert path_traversal_indicators[0].severity == TamperSeverity.HIGH

    def test_absolute_path_in_subject_name(self, tmp_path):
        """Test detection of absolute path in subject name."""
        detector = TamperDetector()

        # Create attestation with absolute path
        attestation_data = {
            "predicate": {
                "buildDefinition": {"externalParameters": {"tools": []}},
                "runDetails": {"builder": {"id": "https://github.com/test/repo"}},
            },
            "subject": [
                {
                    "name": "/tmp/findings.json",  # Absolute path
                    "digest": {"sha256": "abc"},
                }
            ],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        subject_file = tmp_path / "findings.json"
        subject_file.write_text("{}")

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        path_indicators = [
            i for i in indicators if "Suspicious subject name" in i.description
        ]
        assert len(path_indicators) == 1

    def test_missing_required_fields(self, tmp_path):
        """Test detection of missing required fields."""
        detector = TamperDetector()

        # Create attestation with missing required fields
        attestation_data = {
            "predicate": {},  # Missing buildDefinition and runDetails
            "subject": [],  # Empty subject
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        subject_file = tmp_path / "findings.json"
        subject_file.write_text("{}")

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        missing_field_indicators = [
            i for i in indicators if "Missing required fields" in i.description
        ]
        assert len(missing_field_indicators) == 1
        assert missing_field_indicators[0].severity == TamperSeverity.MEDIUM
        assert (
            missing_field_indicators[0].indicator_type
            == TamperIndicatorType.MISSING_FIELD
        )

    def test_localhost_builder(self, tmp_path):
        """Test detection of localhost builder (suspicious)."""
        detector = TamperDetector()

        # Create attestation with localhost builder
        attestation_data = {
            "predicate": {
                "buildDefinition": {"externalParameters": {"tools": []}},
                "runDetails": {"builder": {"id": "http://localhost:8080"}},
            },
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc"}}],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        subject_file = tmp_path / "findings.json"
        subject_file.write_text("{}")

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        localhost_indicators = [
            i for i in indicators if "Suspicious builder ID" in i.description
        ]
        assert len(localhost_indicators) == 1
        assert localhost_indicators[0].severity == TamperSeverity.HIGH

    def test_file_uri_builder(self, tmp_path):
        """Test detection of file:// URI builder (suspicious)."""
        detector = TamperDetector()

        # Create attestation with file:// builder
        attestation_data = {
            "predicate": {
                "buildDefinition": {"externalParameters": {"tools": []}},
                "runDetails": {"builder": {"id": "file:///tmp/builder"}},
            },
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc"}}],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        subject_file = tmp_path / "findings.json"
        subject_file.write_text("{}")

        indicators = detector.check_suspicious_patterns(
            str(subject_file), str(attestation_file)
        )

        file_uri_indicators = [
            i for i in indicators if "Suspicious builder ID" in i.description
        ]
        assert len(file_uri_indicators) == 1


class TestCheckAll:
    """Tests for check_all aggregate method."""

    def test_check_all_no_issues(self, tmp_path):
        """Test check_all with clean attestation (no issues)."""
        detector = TamperDetector()

        # Create valid subject
        subject_data = {"findings": [{"id": "finding1"}]}
        subject_file = tmp_path / "findings.json"
        subject_file.write_text(json.dumps(subject_data))

        # Create valid attestation
        attestation_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": ["trivy", "semgrep"],
                        "profile": "balanced",
                    }
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/test/repo"},
                    "metadata": {
                        "startedOn": "2025-01-15T11:00:00Z",
                        "finishedOn": "2025-01-15T12:00:00Z",
                    },
                },
            },
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc"}}],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_all(
            subject_path=str(subject_file),
            attestation_path=str(attestation_file),
            historical_attestations=None,
        )

        # Should have no critical/high indicators
        critical_or_high = [
            i
            for i in indicators
            if i.severity in [TamperSeverity.CRITICAL, TamperSeverity.HIGH]
        ]
        assert len(critical_or_high) == 0

    @patch("scripts.core.attestation.tamper_detector.datetime")
    def test_check_all_multiple_issues(self, mock_datetime, tmp_path):
        """Test check_all detecting multiple issues."""
        detector = TamperDetector()

        # Mock current time
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_datetime.now.return_value = now
        mock_datetime.fromisoformat = datetime.fromisoformat

        # Create subject with zero findings
        subject_data = {"findings": []}
        subject_file = tmp_path / "findings.json"
        subject_file.write_text(json.dumps(subject_data))

        # Create attestation with multiple issues
        attestation_data = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "tools": ["trivy", "semgrep", "trufflehog", "syft", "checkov"],
                        "profile": "balanced",
                    }
                },
                "runDetails": {
                    "builder": {"id": "http://localhost:8080"},  # Suspicious
                    "metadata": {
                        "startedOn": "2025-01-15T13:00:00Z",  # Future
                        "finishedOn": "2025-01-15T14:00:00Z",  # Future
                    },
                },
            },
            "subject": [
                {
                    "name": "../../etc/passwd",  # Path traversal
                    "digest": {"sha256": "abc"},
                }
            ],
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation_data))

        indicators = detector.check_all(
            subject_path=str(subject_file),
            attestation_path=str(attestation_file),
            historical_attestations=None,
        )

        # Should detect multiple issues
        assert len(indicators) >= 3

        # Check for specific indicators
        future_timestamp = any("future" in i.description.lower() for i in indicators)
        suspicious_builder = any(
            "Suspicious builder ID" in i.description for i in indicators
        )
        path_traversal = any(
            "Suspicious subject name" in i.description for i in indicators
        )

        assert future_timestamp
        assert suspicious_builder
        assert path_traversal


class TestVersionDowngrade:
    """Tests for _is_version_downgrade helper method."""

    def test_major_version_downgrade(self):
        """Test major version downgrade detection (2.0.0 → 1.0.0)."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("1.0.0", "2.0.0")

        assert result is True

    def test_minor_version_downgrade(self):
        """Test minor version downgrade detection (0.50.0 → 0.30.0)."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("0.30.0", "0.50.0")

        assert result is True

    def test_patch_version_downgrade(self):
        """Test patch version downgrade detection (0.50.5 → 0.50.1)."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("0.50.1", "0.50.5")

        assert result is True

    def test_version_upgrade_not_downgrade(self):
        """Test that version upgrades are not flagged."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("0.55.0", "0.50.0")

        assert result is False

    def test_same_version_not_downgrade(self):
        """Test that same version is not a downgrade."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("0.50.0", "0.50.0")

        assert result is False

    def test_version_with_v_prefix(self):
        """Test version comparison with 'v' prefix."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("v0.30.0", "v0.50.0")

        assert result is True

    def test_version_mixed_prefix(self):
        """Test version comparison with mixed 'v' prefix."""
        detector = TamperDetector()

        result = detector._is_version_downgrade("0.30.0", "v0.50.0")

        assert result is True

    def test_invalid_version_format(self):
        """Test handling of invalid version format."""
        detector = TamperDetector()

        # Should not crash, returns False
        result = detector._is_version_downgrade("invalid", "0.50.0")

        assert result is False

    def test_partial_version_numbers(self):
        """Test comparison of partial version numbers (1.0 vs 2.0.0)."""
        detector = TamperDetector()

        # Should pad to 1.0.0 vs 2.0.0
        result = detector._is_version_downgrade("1.0", "2.0.0")

        assert result is True


class TestTamperIndicator:
    """Tests for TamperIndicator dataclass."""

    def test_tamper_indicator_creation(self):
        """Test creating TamperIndicator."""
        indicator = TamperIndicator(
            severity=TamperSeverity.CRITICAL,
            indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
            description="Test anomaly",
            evidence={"key": "value"},
        )

        assert indicator.severity == TamperSeverity.CRITICAL
        assert indicator.indicator_type == TamperIndicatorType.TIMESTAMP_ANOMALY
        assert indicator.description == "Test anomaly"
        assert indicator.evidence == {"key": "value"}
