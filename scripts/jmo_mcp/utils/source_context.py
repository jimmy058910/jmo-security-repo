"""
Extract source code context for security findings.

Provides surrounding code context for AI tools to analyze and suggest fixes.
"""

from pathlib import Path
from typing import Any
import logging

logger = logging.getLogger(__name__)


class SourceContextExtractor:
    """Extract source code context around a finding"""

    def __init__(self, repo_root: Path):
        """
        Initialize source context extractor.

        Args:
            repo_root: Root directory of repository being scanned
        """
        self.repo_root = Path(repo_root)

    def get_context(
        self,
        file_path: str,
        start_line: int,
        end_line: int | None = None,
        context_lines: int = 20,
    ) -> dict[str, Any]:
        """
        Get source code context around a finding.

        Args:
            file_path: Relative path to file (from repo root)
            start_line: Start line of finding (1-indexed)
            end_line: End line of finding (1-indexed, optional)
            context_lines: Number of lines of context to include (default: 20)

        Returns:
            Dictionary with source code context:
            {
                "path": str,
                "lines": str,  # Source code with context
                "language": str,
                "start_line": int,
                "end_line": int,
                "error": Optional[str]  # If file read failed
            }
        """
        full_path = self.repo_root / file_path

        if not full_path.exists():
            logger.error(f"File not found: {full_path}")
            return {
                "path": file_path,
                "lines": "",
                "language": "unknown",
                "start_line": start_line,
                "end_line": end_line or start_line,
                "error": "File not found",
            }

        try:
            with open(full_path, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()

            # Calculate context window
            if end_line is None:
                end_line = start_line

            context_start = max(1, start_line - context_lines)
            context_end = min(len(all_lines), end_line + context_lines)

            # Extract context lines (convert to 0-indexed)
            context = all_lines[context_start - 1 : context_end]

            # Detect language from file extension
            language = self._detect_language(file_path)

            logger.info(
                f"Extracted {len(context)} lines of context for {file_path}:{start_line}"
            )

            return {
                "path": file_path,
                "lines": "".join(context),
                "language": language,
                "start_line": context_start,
                "end_line": context_end,
            }

        except UnicodeDecodeError:
            logger.warning(f"Binary file, cannot extract context: {file_path}")
            return {
                "path": file_path,
                "lines": "",
                "language": "binary",
                "start_line": start_line,
                "end_line": end_line or start_line,
                "error": "Binary file",
            }
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return {
                "path": file_path,
                "lines": "",
                "language": "unknown",
                "start_line": start_line,
                "end_line": end_line or start_line,
                "error": str(e),
            }

    def _detect_language(self, file_path: str) -> str:
        """
        Detect programming language from file extension.

        Args:
            file_path: Path to file

        Returns:
            Language name (lowercase)
        """
        ext = Path(file_path).suffix.lower()

        # Comprehensive language mapping
        language_map = {
            # Programming languages
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".hxx": "cpp",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".kts": "kotlin",
            ".scala": "scala",
            ".pl": "perl",
            ".pm": "perl",
            ".lua": "lua",
            ".r": "r",
            ".m": "objectivec",
            ".mm": "objectivec",
            # Shell scripts
            ".sh": "bash",
            ".bash": "bash",
            ".zsh": "zsh",
            ".fish": "fish",
            ".ps1": "powershell",
            ".psm1": "powershell",
            # Data formats
            ".yml": "yaml",
            ".yaml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".toml": "toml",
            ".ini": "ini",
            ".conf": "conf",
            ".cfg": "cfg",
            # Web technologies
            ".html": "html",
            ".htm": "html",
            ".css": "css",
            ".scss": "scss",
            ".sass": "sass",
            ".less": "less",
            ".vue": "vue",
            ".svelte": "svelte",
            # SQL and databases
            ".sql": "sql",
            ".pgsql": "postgresql",
            ".mysql": "mysql",
            # Infrastructure as Code
            ".tf": "terraform",
            ".tfvars": "terraform",
            ".hcl": "hcl",
            # Dockerfile
            ".dockerfile": "dockerfile",
            # Makefile
            ".mk": "makefile",
            # Markdown
            ".md": "markdown",
            ".markdown": "markdown",
            ".rst": "restructuredtext",
        }

        # Special cases (filenames without extensions)
        filename = Path(file_path).name.lower()
        if filename == "dockerfile":
            return "dockerfile"
        if filename == "makefile":
            return "makefile"
        if filename.startswith(".gitignore"):
            return "gitignore"
        if filename.startswith(".env"):
            return "dotenv"

        return language_map.get(ext, "unknown")

    def get_full_file_content(self, file_path: str) -> dict[str, Any]:
        """
        Get entire file content (for smaller files).

        Args:
            file_path: Relative path to file

        Returns:
            Dictionary with full file content
        """
        full_path = self.repo_root / file_path

        if not full_path.exists():
            return {
                "path": file_path,
                "content": "",
                "language": "unknown",
                "error": "File not found",
            }

        try:
            with open(full_path, encoding="utf-8", errors="replace") as f:
                content = f.read()

            language = self._detect_language(file_path)

            return {
                "path": file_path,
                "content": content,
                "language": language,
                "line_count": len(content.splitlines()),
            }

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return {
                "path": file_path,
                "content": "",
                "language": "unknown",
                "error": str(e),
            }
