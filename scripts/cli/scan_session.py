"""
Scan session checkpointing for crash recovery and resume.

Provides crash-resilient scan sessions that checkpoint after each target
completes, enabling resume without re-scanning completed targets.

Session file: .jmo/scan-session.json

Architecture:
1. Before scanning, check for existing session file
2. If valid session exists and config matches, offer resume
3. During scan, checkpoint after each target completes (atomic write)
4. On clean exit, delete session file
5. On crash/interrupt, session file persists for next run

Atomic writes use tempfile + os.replace() which is atomic on both NTFS and POSIX.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Session file format version for forward compatibility
SESSION_VERSION = 1


@dataclass
class ToolRecord:
    """Status of a single tool within a target scan."""

    name: str
    status: str = "pending"  # pending, completed, failed, skipped
    error: str = ""
    output_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "error": self.error,
            "output_file": self.output_file,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRecord:
        return cls(
            name=data["name"],
            status=data.get("status", "pending"),
            error=data.get("error", ""),
            output_file=data.get("output_file", ""),
        )


@dataclass
class TargetRecord:
    """Status of a single scan target."""

    target_type: str  # repo, image, iac, url, gitlab, k8s
    target_id: str  # Unique identifier for this target
    completed: bool = False
    tools: dict[str, ToolRecord] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "completed": self.completed,
            "tools": {name: tr.to_dict() for name, tr in self.tools.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetRecord:
        tools = {}
        for name, tool_data in data.get("tools", {}).items():
            tools[name] = ToolRecord.from_dict(tool_data)
        return cls(
            target_type=data["target_type"],
            target_id=data["target_id"],
            completed=data.get("completed", False),
            tools=tools,
        )


@dataclass
class ScanSession:
    """Checkpoint state for a scan session."""

    session_id: str
    profile: str
    config_hash: str
    started_at: float
    pid: int
    targets: dict[str, TargetRecord] = field(default_factory=dict)
    version: int = SESSION_VERSION

    @property
    def completed_targets(self) -> list[str]:
        """Return list of completed target IDs."""
        return [tid for tid, t in self.targets.items() if t.completed]

    @property
    def pending_targets(self) -> list[str]:
        """Return list of pending (not completed) target IDs."""
        return [tid for tid, t in self.targets.items() if not t.completed]

    @property
    def total_targets(self) -> int:
        return len(self.targets)

    @property
    def completed_count(self) -> int:
        return len(self.completed_targets)

    def register_target(
        self, target_type: str, target_id: str, tools: list[str]
    ) -> None:
        """Register a target for scanning."""
        tool_records = {name: ToolRecord(name=name) for name in tools}
        self.targets[target_id] = TargetRecord(
            target_type=target_type,
            target_id=target_id,
            tools=tool_records,
        )

    def mark_target_complete(self, target_id: str, statuses: dict[str, bool]) -> None:
        """Mark a target as completed with tool statuses."""
        if target_id not in self.targets:
            return
        target = self.targets[target_id]
        target.completed = True
        for tool_name, success in statuses.items():
            if tool_name.startswith("__"):
                continue  # Skip metadata keys like __attempts__
            if tool_name in target.tools:
                target.tools[tool_name].status = "completed" if success else "failed"

    def is_target_completed(self, target_id: str) -> bool:
        """Check if a specific target has been completed."""
        return target_id in self.targets and self.targets[target_id].completed

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "session_id": self.session_id,
            "profile": self.profile,
            "config_hash": self.config_hash,
            "started_at": self.started_at,
            "pid": self.pid,
            "targets": {tid: t.to_dict() for tid, t in self.targets.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanSession:
        targets = {}
        for tid, target_data in data.get("targets", {}).items():
            targets[tid] = TargetRecord.from_dict(target_data)
        return cls(
            session_id=data["session_id"],
            profile=data.get("profile", ""),
            config_hash=data["config_hash"],
            started_at=data.get("started_at", 0.0),
            pid=data.get("pid", 0),
            targets=targets,
            version=data.get("version", SESSION_VERSION),
        )


def compute_config_hash(config_path: Path | str) -> str:
    """Compute SHA-256 hash of config file for change detection.

    Args:
        config_path: Path to jmo.yml config file

    Returns:
        Hex digest of SHA-256 hash, or empty string if file doesn't exist
    """
    config_path = Path(config_path)
    if not config_path.exists():
        return ""
    try:
        content = config_path.read_bytes()
        return hashlib.sha256(content).hexdigest()
    except OSError:
        return ""


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON data atomically using tempfile + os.replace().

    os.replace() is atomic on both NTFS (same volume) and POSIX filesystems.
    We create the temp file in the same directory to ensure same-volume operation.

    Args:
        path: Target file path
        data: JSON-serializable data
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2)

    # Create temp file in same directory for atomic replace
    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=".scan-session-",
        suffix=".tmp",
    )
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        fd = -1  # Mark as closed
        os.replace(tmp_path, str(path))
    except Exception:
        if fd >= 0:
            os.close(fd)
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save_session(session: ScanSession, session_path: Path) -> None:
    """Save session checkpoint to disk (atomic write).

    Args:
        session: Session to save
        session_path: Path to session file
    """
    try:
        _atomic_write_json(session_path, session.to_dict())
    except Exception as e:
        logger.warning(f"Failed to save scan session checkpoint: {e}")


def load_session(session_path: Path) -> ScanSession | None:
    """Load session from disk.

    Args:
        session_path: Path to session file

    Returns:
        ScanSession if valid, None if missing/corrupt/wrong version
    """
    if not session_path.exists():
        return None
    try:
        data = json.loads(session_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("version", 0) != SESSION_VERSION:
            logger.warning(
                f"Session file version mismatch: expected {SESSION_VERSION}, "
                f"got {data.get('version', 'unknown')}"
            )
            return None
        return ScanSession.from_dict(data)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        logger.warning(f"Corrupt session file {session_path}: {e}")
        return None


def delete_session(session_path: Path) -> None:
    """Delete session file (clean exit).

    Args:
        session_path: Path to session file
    """
    try:
        if session_path.exists():
            session_path.unlink()
    except OSError as e:
        logger.warning(f"Failed to delete session file: {e}")


def validate_session_results(session: ScanSession, results_dir: Path) -> bool:
    """Verify that completed target output files still exist on disk.

    If output files were deleted (e.g., results directory wiped), the session
    is invalid and should be discarded.

    Args:
        session: Session to validate
        results_dir: Base results directory

    Returns:
        True if all completed targets have output files, False otherwise
    """
    for target_id, target in session.targets.items():
        if not target.completed:
            continue
        # Check if the target's output directory exists
        target_type_dir_map = {
            "repo": "individual-repos",
            "image": "individual-images",
            "iac": "individual-iac",
            "url": "individual-web",
            "gitlab": "individual-gitlab",
            "k8s": "individual-k8s",
        }
        type_dir = target_type_dir_map.get(target.target_type, "")
        if not type_dir:
            continue

        type_path = results_dir / type_dir
        if not type_path.exists():
            logger.info(
                f"Results directory missing for {target.target_type}: {type_path}"
            )
            return False

        # Check for at least one output file (any .json file in the target's subdir)
        # Target dirs use sanitized names, check for any JSON output
        has_output = any(type_path.rglob("*.json"))
        if not has_output:
            logger.info(f"No output files found in {type_path}")
            return False

    return True


def format_session_summary(session: ScanSession) -> str:
    """Format human-readable session summary.

    Args:
        session: Session to summarize

    Returns:
        Summary string like "Previous scan (started 45min ago, 18/29 targets, deep profile)"
    """
    elapsed = time.time() - session.started_at

    if elapsed < 60:
        time_str = f"{int(elapsed)}s ago"
    elif elapsed < 3600:
        time_str = f"{int(elapsed / 60)}min ago"
    elif elapsed < 86400:
        hours = elapsed / 3600
        time_str = f"{hours:.1f}h ago"
    else:
        days = elapsed / 86400
        time_str = f"{days:.1f}d ago"

    completed = session.completed_count
    total = session.total_targets
    profile = session.profile or "custom"

    return (
        f"Previous scan (started {time_str}, "
        f"{completed}/{total} targets, "
        f"{profile} profile)"
    )
