"""Base classes and utilities for wizard workflows."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
import re
import subprocess  # nosec B404
import yaml


class TargetDetector:
    """Unified target detection for wizard workflows."""

    def detect_repos(self, search_dir: Optional[Path] = None) -> List[Path]:
        """Detect Git repositories in directory.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of Path objects pointing to Git repositories
        """
        if search_dir is None:
            search_dir = Path.cwd()

        repos: List[Path] = []
        if not search_dir.exists():
            return repos

        for item in search_dir.iterdir():
            if item.is_dir() and (item / ".git").exists():
                repos.append(item)

        return repos

    def detect_images(self, search_dir: Optional[Path] = None) -> List[str]:
        """Detect container images from docker-compose.yml, Dockerfiles.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of image names
        """
        if search_dir is None:
            search_dir = Path.cwd()

        images = []

        # From docker-compose.yml
        compose_file = search_dir / "docker-compose.yml"
        if compose_file.exists():
            try:
                compose = yaml.safe_load(compose_file.read_text())
                for service in compose.get("services", {}).values():
                    if "image" in service:
                        images.append(service["image"])
            except (yaml.YAMLError, FileNotFoundError, KeyError):
                pass

        # From Dockerfiles (extract FROM lines)
        for dockerfile in search_dir.glob("**/Dockerfile*"):
            try:
                content = dockerfile.read_text()
                for match in re.finditer(r"FROM\s+([\w/:@.-]+)", content):
                    images.append(match.group(1))
            except (FileNotFoundError, UnicodeDecodeError):
                pass

        return list(set(images))  # Deduplicate

    def detect_iac(self, search_dir: Optional[Path] = None) -> List[Path]:
        """Detect IaC files (Terraform, CloudFormation, K8s).

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of IaC file paths
        """
        if search_dir is None:
            search_dir = Path.cwd()

        iac_files: List[Path] = []

        # Terraform
        iac_files.extend(search_dir.glob("**/*.tf"))
        iac_files.extend(search_dir.glob("**/*.tfstate"))

        # CloudFormation
        for pattern in ["**/*cloudformation*.yml", "**/*cloudformation*.yaml"]:
            iac_files.extend(search_dir.glob(pattern))

        # Kubernetes
        iac_files.extend(search_dir.glob("**/k8s/**/*.yml"))
        iac_files.extend(search_dir.glob("**/kubernetes/**/*.yml"))

        return iac_files

    def detect_web_apps(self, search_dir: Optional[Path] = None) -> List[str]:
        """Detect web applications (infer from config files).

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of inferred URLs
        """
        if search_dir is None:
            search_dir = Path.cwd()

        urls = []

        # From docker-compose.yml ports
        compose_file = search_dir / "docker-compose.yml"
        if compose_file.exists():
            try:
                compose = yaml.safe_load(compose_file.read_text())
                for service in compose.get("services", {}).values():
                    ports = service.get("ports", [])
                    for port in ports:
                        if isinstance(port, str) and ":" in port:
                            host_port = port.split(":")[0]
                            urls.append(f"http://localhost:{host_port}")
            except (yaml.YAMLError, FileNotFoundError, KeyError):
                pass

        # Defaults for common frameworks
        if (search_dir / "package.json").exists():
            urls.append("http://localhost:3000")  # React/Next.js

        return list(set(urls))

    def detect_package_files(self, search_dir: Optional[Path] = None) -> List[Path]:
        """Detect package manifest files across languages.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of package manifest file paths
        """
        if search_dir is None:
            search_dir = Path.cwd()

        package_files: List[Path] = []

        # Python
        package_files.extend(search_dir.glob("**/requirements.txt"))
        package_files.extend(search_dir.glob("**/pyproject.toml"))
        package_files.extend(search_dir.glob("**/setup.py"))
        package_files.extend(search_dir.glob("**/Pipfile"))

        # JavaScript/Node.js
        package_files.extend(search_dir.glob("**/package.json"))

        # Go
        package_files.extend(search_dir.glob("**/go.mod"))

        # Rust
        package_files.extend(search_dir.glob("**/Cargo.toml"))

        # Java/Maven
        package_files.extend(search_dir.glob("**/pom.xml"))

        # Java/Gradle
        package_files.extend(search_dir.glob("**/build.gradle"))
        package_files.extend(search_dir.glob("**/build.gradle.kts"))

        # Ruby
        package_files.extend(search_dir.glob("**/Gemfile"))

        # .NET
        package_files.extend(search_dir.glob("**/*.csproj"))

        return list(set(package_files))

    def detect_lock_files(self, search_dir: Optional[Path] = None) -> List[Path]:
        """Detect lock files for reproducible dependency scans.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of lock file paths
        """
        if search_dir is None:
            search_dir = Path.cwd()

        lock_files: List[Path] = []

        # Python
        lock_files.extend(search_dir.glob("**/requirements-lock.txt"))
        lock_files.extend(search_dir.glob("**/poetry.lock"))
        lock_files.extend(search_dir.glob("**/Pipfile.lock"))

        # JavaScript/Node.js
        lock_files.extend(search_dir.glob("**/package-lock.json"))
        lock_files.extend(search_dir.glob("**/yarn.lock"))
        lock_files.extend(search_dir.glob("**/pnpm-lock.yaml"))

        # Go
        lock_files.extend(search_dir.glob("**/go.sum"))

        # Rust
        lock_files.extend(search_dir.glob("**/Cargo.lock"))

        # Ruby
        lock_files.extend(search_dir.glob("**/Gemfile.lock"))

        return list(set(lock_files))


class PromptHelper:
    """Helper for interactive prompts with colored output."""

    # ANSI color codes
    COLORS = {
        "blue": "\x1b[36m",
        "cyan": "\x1b[96m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "red": "\x1b[31m",
        "magenta": "\x1b[35m",
        "bold": "\x1b[1m",
        "dim": "\x1b[2m",
        "reset": "\x1b[0m",
    }

    # Visual elements
    ICONS = {
        "check": "✓",
        "cross": "✗",
        "arrow": "→",
        "bullet": "•",
        "star": "★",
        "rocket": "🚀",
        "lock": "🔒",
        "package": "📦",
        "chart": "📊",
        "warning": "⚠️",
        "info": "ℹ️",
        "success": "✅",
        "hourglass": "⏳",
    }

    def colorize(self, text: str, color: str) -> str:
        """Apply ANSI color codes to text.

        Args:
            text: Text to colorize
            color: Color name (blue, cyan, green, yellow, red, magenta, bold, dim)

        Returns:
            Colorized text with reset code
        """
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def print_header(self, text: str, icon: str = "star") -> None:
        """Print a formatted section header with icon.

        Args:
            text: Header text
            icon: Icon name (star, rocket, lock, package, chart)
        """
        print()
        print(self.colorize("╔" + "═" * 68 + "╗", "cyan"))
        icon_char = self.ICONS.get(icon, self.ICONS["star"])
        header_text = f"{icon_char}  {text}  {icon_char}"
        print(self.colorize(f"║{header_text.center(68)}║", "bold"))
        print(self.colorize("╚" + "═" * 68 + "╝", "cyan"))
        print()

    def print_step(self, step: int, total: int, text: str) -> None:
        """Print a step indicator with progress bar.

        Args:
            step: Current step number
            total: Total number of steps
            text: Step description
        """
        # Progress bar
        progress_width = 20
        filled = int((step / total) * progress_width)
        bar = "█" * filled + "░" * (progress_width - filled)
        percentage = int((step / total) * 100)

        # Step indicator
        step_text = f"[Step {step}/{total}]"
        progress_text = f"[{bar}] {percentage}%"

        print()
        print(self.colorize("─" * 70, "dim"))
        print(
            self.colorize(f"{self.ICONS['arrow']} {step_text} {text}", "bold")
            + f"  {self.colorize(progress_text, 'cyan')}"
        )
        print()

    def print_success(self, message: str) -> None:
        """Print a success message.

        Args:
            message: Success message
        """
        print(self.colorize(f"{self.ICONS['success']} {message}", "green"))

    def print_info(self, message: str) -> None:
        """Print an info message.

        Args:
            message: Info message
        """
        print(self.colorize(f"{self.ICONS['info']} {message}", "cyan"))

    def print_warning(self, message: str) -> None:
        """Print a warning message.

        Args:
            message: Warning message
        """
        print(self.colorize(f"{self.ICONS['warning']} {message}", "yellow"))

    def print_error(self, message: str) -> None:
        """Print an error message.

        Args:
            message: Error message
        """
        print(self.colorize(f"{self.ICONS['cross']} {message}", "red"))

    def print_summary_box(self, title: str, items: List[str]) -> None:
        """Print a summary box with items.

        Args:
            title: Box title
            items: List of items to display
        """
        print()
        print(self.colorize("┌─ " + title + " " + "─" * (66 - len(title)), "cyan"))
        for item in items:
            print(self.colorize(f"│ {self.ICONS['bullet']} {item}", "dim"))
        print(self.colorize("└" + "─" * 68, "cyan"))
        print()

    def prompt_choice(
        self, question: str, choices: List[str], default: Optional[str] = None
    ) -> str:
        """Prompt user to select from choices.

        Args:
            question: Question to ask
            choices: List of choice strings
            default: Default choice (optional)

        Returns:
            Selected choice
        """
        print(f"\n{question}")
        for i, choice in enumerate(choices, 1):
            prefix = ">" if choice == default else " "
            print(f"  {prefix} {i}. {choice}")

        while True:
            if default:
                response = input(f"Choice [default: {default}]: ").strip()
            else:
                response = input("Choice: ").strip()

            if not response and default:
                return default

            try:
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                pass

            print(f"Invalid choice. Enter 1-{len(choices)}")

    def prompt_yes_no(self, question: str, default: bool = True) -> bool:
        """Prompt user for yes/no.

        Args:
            question: Question to ask
            default: Default value

        Returns:
            True for yes, False for no
        """
        default_str = "Y/n" if default else "y/N"
        while True:
            response = input(f"{question} [{default_str}]: ").strip().lower()
            if not response:
                return default
            if response in ("y", "yes"):
                return True
            if response in ("n", "no"):
                return False
            print("Please enter 'y' or 'n'")

    def prompt_text(self, question: str, default: str = "") -> str:
        """Prompt user for text input.

        Args:
            question: Question to ask
            default: Default value

        Returns:
            User input or default
        """
        if default:
            prompt = f"{question} [{default}]: "
        else:
            prompt = f"{question}: "

        response = input(prompt).strip()
        return response if response else default

    def confirm(self, message: str) -> bool:
        """Confirm action with yes/no prompt.

        Args:
            message: Confirmation message

        Returns:
            True if confirmed, False otherwise
        """
        return self.prompt_yes_no(message, default=True)


class ArtifactGenerator:
    """Generate reusable scan artifacts (Makefile, GHA, scripts)."""

    def generate_makefile(self, command: List[str], output_path: Path) -> None:
        """Generate Makefile with scan target.

        Args:
            command: Command list to run
            output_path: Path to write Makefile
        """
        from scripts.cli.wizard_generators import generate_makefile_target

        generate_makefile_target(command, output_path)  # type: ignore[arg-type]

    def generate_github_actions(self, command: List[str], output_path: Path) -> None:
        """Generate GitHub Actions workflow.

        Args:
            command: Command list to run
            output_path: Path to write workflow YAML
        """
        from scripts.cli.wizard_generators import generate_github_actions

        generate_github_actions(command, output_path)  # type: ignore[arg-type]

    def generate_shell_script(self, command: List[str], output_path: Path) -> None:
        """Generate shell script.

        Args:
            command: Command list to run
            output_path: Path to write shell script
        """
        from scripts.cli.wizard_generators import generate_shell_script

        generate_shell_script(command, output_path)  # type: ignore[arg-type]


class BaseWizardFlow(ABC):
    """Abstract base class for wizard workflows."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize workflow.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.detector = TargetDetector()
        self.generator = ArtifactGenerator()
        self.prompter = PromptHelper()

    @abstractmethod
    def detect_targets(self) -> Dict[str, List]:
        """Detect scannable targets for this workflow.

        Returns:
            Dictionary of target types to target lists
        """
        pass

    @abstractmethod
    def prompt_user(self) -> Dict[str, Any]:
        """Prompt user for workflow-specific options.

        Returns:
            Dictionary of user selections
        """
        pass

    @abstractmethod
    def build_command(self, targets: Dict, options: Dict) -> List[str]:
        """Build jmo scan command from targets and options.

        Args:
            targets: Detected targets
            options: User options

        Returns:
            Command as list of strings
        """
        pass

    def execute(self) -> int:
        """Execute the workflow (template method) with progress tracking.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        total_steps = 6  # Detection, User Input, Command Build, Preflight, Confirmation, Execution

        # Step 1: Detect targets
        self.prompter.print_step(1, total_steps, "Detecting scan targets...")
        targets = self.detect_targets()
        if not targets or all(not v for v in targets.values()):
            self.prompter.print_error("No targets detected")
            return 1

        # Store targets for workflows to access
        self.detected_targets = targets

        self.prompter.print_success(
            f"Detected {sum(len(v) if isinstance(v, list) else 1 for v in targets.values() if v)} targets"
        )

        # Step 2: User input (workflow-specific)
        self.prompter.print_step(2, total_steps, "Gathering configuration options...")
        options = self.prompt_user()
        self.prompter.print_success("Configuration complete")

        # Step 3: Build command
        self.prompter.print_step(3, total_steps, "Building scan command...")
        command = self.build_command(targets, options)
        self.prompter.print_success("Command built successfully")

        # Step 4: Preflight summary
        self.prompter.print_step(4, total_steps, "Preparing preflight summary...")
        preflight_items = [
            f"Profile: {options.get('profile', 'default')}",
            f"Command: {' '.join(command)}",
            f"Estimated time: {self._estimate_time(options.get('profile', 'balanced'))}",
        ]
        self.prompter.print_summary_box("🚀 Preflight Check", preflight_items)

        # Step 5: Confirmation
        self.prompter.print_step(5, total_steps, "Awaiting confirmation...")
        if not self.prompter.confirm("Execute scan?"):
            self.prompter.print_warning("Scan cancelled by user")
            return 0

        # Step 6: Execute scan
        self.prompter.print_step(6, total_steps, "Executing security scan...")
        self.prompter.print_info("Scan in progress... This may take several minutes.")
        try:
            result = subprocess.run(command, check=False)  # nosec B603
            if result.returncode == 0:
                self.prompter.print_success("Scan completed successfully!")
            else:
                self.prompter.print_error(
                    f"Scan completed with errors (exit code {result.returncode})"
                )
            return result.returncode
        except Exception as e:
            self.prompter.print_error(f"Scan failed: {e}")
            return 1

    def _estimate_time(self, profile: str) -> str:
        """Estimate scan time based on profile.

        Args:
            profile: Scan profile name

        Returns:
            Time estimate string
        """
        estimates = {
            "fast": "5-8 minutes",
            "balanced": "15-20 minutes",
            "deep": "30-60 minutes",
        }
        return estimates.get(profile, "15-20 minutes")
