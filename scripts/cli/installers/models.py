"""Data models for tool installation."""

from dataclasses import dataclass, field


@dataclass
class InstallResult:
    """Result of a tool installation attempt."""

    tool_name: str
    success: bool
    method: str = ""
    message: str = ""
    version_installed: str | None = None
    version_expected: str | None = None
    version_mismatch: bool = False
    duration_seconds: float = 0.0
    # A non-fatal caveat on an otherwise successful install (Task O2 fix
    # round 1, review Important #1): `print_install_progress` renders
    # `.message` only on the FAILURE branch, so a note appended to
    # `.message` on a `success=True` result never reached the CLI's own
    # summary table -- only the logger did. `.warning` is rendered under
    # the [OK] row instead, regardless of success. None for every tool that
    # has nothing to add (the overwhelming majority).
    warning: str | None = None


@dataclass
class InstallProgress:
    """Progress tracking for batch installations."""

    total: int = 0
    completed: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[InstallResult] = field(default_factory=list)

    @property
    def current(self) -> int:
        return self.completed

    def add_result(self, result: InstallResult) -> None:
        self.results.append(result)
        self.completed += 1
        if result.success:
            self.successful += 1
        else:
            self.failed += 1
