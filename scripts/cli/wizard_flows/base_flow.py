"""Base classes and utilities for wizard workflows."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re
import subprocess  # nosec B404
import yaml  # type: ignore


class TargetDetector:
    """Unified target detection for wizard workflows."""

    def detect_repos(self, search_dir: Path = None) -> List[Path]:
        """Detect Git repositories in directory.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of Path objects pointing to Git repositories
        """
        if search_dir is None:
            search_dir = Path.cwd()

        repos = []
        if not search_dir.exists():
            return repos

        for item in search_dir.iterdir():
            if item.is_dir() and (item / ".git").exists():
                repos.append(item)

        return repos

    def detect_images(self, search_dir: Path = None) -> List[str]:
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

    def detect_iac(self, search_dir: Path = None) -> List[Path]:
        """Detect IaC files (Terraform, CloudFormation, K8s).

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of IaC file paths
        """
        if search_dir is None:
            search_dir = Path.cwd()

        iac_files = []

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

    def detect_web_apps(self, search_dir: Path = None) -> List[str]:
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


class PromptHelper:
    """Helper for interactive prompts with colored output."""

    # ANSI color codes
    COLORS = {
        "blue": "\x1b[36m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "red": "\x1b[31m",
        "bold": "\x1b[1m",
        "reset": "\x1b[0m",
    }

    def colorize(self, text: str, color: str) -> str:
        """Apply ANSI color codes to text.

        Args:
            text: Text to colorize
            color: Color name (blue, green, yellow, red, bold)

        Returns:
            Colorized text with reset code
        """
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def print_header(self, text: str) -> None:
        """Print a formatted section header."""
        print()
        print(self.colorize("=" * 70, "blue"))
        print(self.colorize(text.center(70), "bold"))
        print(self.colorize("=" * 70, "blue"))
        print()

    def print_step(self, step: int, total: int, text: str) -> None:
        """Print a step indicator."""
        print(self.colorize(f"\n[Step {step}/{total}] {text}", "blue"))

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

        generate_makefile_target(command, output_path)

    def generate_github_actions(self, command: List[str], output_path: Path) -> None:
        """Generate GitHub Actions workflow.

        Args:
            command: Command list to run
            output_path: Path to write workflow YAML
        """
        from scripts.cli.wizard_generators import generate_github_actions

        generate_github_actions(command, output_path)

    def generate_shell_script(self, command: List[str], output_path: Path) -> None:
        """Generate shell script.

        Args:
            command: Command list to run
            output_path: Path to write shell script
        """
        from scripts.cli.wizard_generators import generate_shell_script

        generate_shell_script(command, output_path)


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
        """Execute the workflow (template method).

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        # 1. Detect targets
        targets = self.detect_targets()
        if not targets or all(not v for v in targets.values()):
            print(self.prompter.colorize("❌ No targets detected.", "red"))
            return 1

        # 2. Display targets
        self.prompter.print_header("Detected Targets")
        for target_type, target_list in targets.items():
            if target_list:
                print(
                    f"  {self.prompter.colorize('✓', 'green')} {target_type.replace('_', ' ').title()}: {len(target_list)}"
                )

        # 3. Prompt user
        options = self.prompt_user()

        # 4. Build command
        command = self.build_command(targets, options)

        # 5. Display preflight summary
        self.prompter.print_header("Preflight Summary")
        print(f"  Command: {' '.join(command)}")

        # 6. Confirm execution
        if not self.prompter.confirm("\nExecute scan?"):
            print(self.prompter.colorize("❌ Cancelled.", "yellow"))
            return 0

        # 7. Execute command
        try:
            result = subprocess.run(command, check=False)  # nosec B603
            return result.returncode
        except Exception as e:
            print(self.prompter.colorize(f"❌ Scan failed: {e}", "red"))
            return 1
