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
