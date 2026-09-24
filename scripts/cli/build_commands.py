"""
CLI command handlers for `jmo build`.

Builds the JMo Security Docker image from ``Dockerfile``, replacing the
Makefile docker-* targets. There is one image; it carries every scanner in the
tool matrix plus the policy engine.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

from scripts.core.tool_utils import tool_exists

# The one Dockerfile the image is built from.
DOCKERFILE = "Dockerfile"

# Default registry configuration. The org must match what release.yml pushes to
# -- `IMAGE_NAME_GHCR: ${{ github.repository_owner }}/jmo-security` -- which is
# `jimmy058910`, not `jmosecurity`. With the old value `jmo build --push` aimed
# at a namespace this project does not own, and `jmo build test` pulled from it.
DEFAULT_REGISTRY = "ghcr.io"
DEFAULT_ORG = "jimmy058910"
DEFAULT_IMAGE = "jmo-security"

# `docker build` compiles and downloads every scanner, so its budget is generous;
# the others are bounded so a wedged daemon cannot hang the command forever.
BUILD_TIMEOUT = 7200
PUSH_TIMEOUT = 1800
RUN_TIMEOUT = 300


def _image_ref(
    tag: str,
    registry: str,
    org: str,
    image_name: str,
    local: bool,
) -> str:
    """Return the image reference, matching what release.yml publishes.

    release.yml publishes one image, tagged ``:latest`` and semver (``:1.0.2``,
    ``:1.0``, ``:1``) and nothing else, so a registry reference is the bare tag.
    The v1.x ``:<variant>`` and ``:<version>-<variant>`` families are no longer
    built; naming one would pull a frozen v1.x image without any error.
    """
    if local:
        return f"{image_name}:local"
    return f"{registry}/{org}/{image_name}:{tag}"


def _detect_arch() -> str:
    """Detect target architecture for Docker builds."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    elif machine in ("aarch64", "arm64"):
        return "arm64"
    return "amd64"  # Default fallback


def _check_docker() -> bool:
    """Check if Docker is available and running."""
    if not tool_exists("docker", warn=False):
        print("Error: Docker not found in PATH", file=sys.stderr)
        return False

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            print("Error: Docker daemon not running", file=sys.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("Error: Docker daemon not responding", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error checking Docker: {e}", file=sys.stderr)
        return False

    return True


def _find_repo_root() -> Path | None:
    """Find the repository root (a directory holding versions.yaml and the Dockerfile).

    The marker is the file this command builds. When it named a file the tree
    no longer had -- #303 renamed ``Dockerfile`` to a per-variant name on
    2026-04-19 and nothing here followed -- the predicate was unsatisfiable
    anywhere, and `jmo build` answered every invocation with "Cannot find
    repository root" from v1.0.2 through v1.0.8.
    """
    current = Path.cwd()
    for parent in [current, *current.parents]:
        if (parent / "versions.yaml").exists() and (parent / DOCKERFILE).exists():
            return parent
    return None


def _validate_versions(repo_root: Path) -> bool:
    """
    Validate that all versions in versions.yaml exist upstream.

    Returns True if validation passes or is skipped, False on failure.
    """
    validate_script = repo_root / "scripts" / "dev" / "update_versions.py"
    if not validate_script.exists():
        print(
            f"Version validation script not found: {validate_script}",
            file=sys.stderr,
        )
        print(
            "Cannot verify tool versions. Use --skip-validate to build anyway.",
            file=sys.stderr,
        )
        return False

    print("Validating tool versions...")
    try:
        # `text=True` alone decodes with the *parent's* locale codec. On a
        # cp1252 console `update_versions.py --validate` emits bytes that codec
        # cannot decode, and the failure is raised inside subprocess's reader
        # thread, where it is swallowed -- so `result.stdout` came back
        # truncated with only a stray traceback on the console to show for it.
        # See "Subprocess tests: pin BOTH ends" in
        # .claude/rules/testing.cross-platform.rules.md.
        result = subprocess.run(
            [sys.executable, str(validate_script), "--validate"],
            cwd=str(repo_root),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            print("Version validation failed:", file=sys.stderr)
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return False
        print("All versions validated successfully")
        return True
    except subprocess.TimeoutExpired:
        # Was `return True`. A gate that never completed has not passed, and
        # this timeout is a real risk rather than a theoretical one: --validate
        # makes a network call per tool to PyPI and the GitHub API against a
        # 120s budget, and the GitHub calls are rate-limited without a
        # GITHUB_TOKEN. `--skip-validate` already exists for callers who want
        # to bypass the check, so the error paths do not need to be lenient to
        # keep the command usable (#939).
        print(
            "Version validation timed out after 120s (it makes a network call "
            "per tool; GitHub is rate-limited without GITHUB_TOKEN).",
            file=sys.stderr,
        )
        print("Use --skip-validate to build without it.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Version validation failed to run: {e}", file=sys.stderr)
        print("Use --skip-validate to build without it.", file=sys.stderr)
        return False


def _build_image(
    tag: str,
    repo_root: Path,
    registry: str,
    org: str,
    image_name: str,
    local: bool = False,
    no_cache: bool = False,
    push: bool = False,
    platform_target: str | None = None,
) -> int:
    """Build the Docker image, and push it when asked."""
    dockerfile_path = repo_root / DOCKERFILE
    if not dockerfile_path.exists():
        print(f"Error: Dockerfile not found: {dockerfile_path}", file=sys.stderr)
        return 1

    full_tag = _image_ref(tag, registry, org, image_name, local)
    arch = platform_target or _detect_arch()

    print("Building the JMo Security image...")
    print(f"  Dockerfile: {DOCKERFILE}")
    print(f"  Tag: {full_tag}")
    print(f"  Architecture: {arch}")

    cmd = [
        "docker",
        "build",
        "--build-arg",
        f"TARGETARCH={arch}",
        "-f",
        str(dockerfile_path),
        "-t",
        full_tag,
    ]

    if no_cache:
        cmd.append("--no-cache")

    cmd.append(str(repo_root))

    try:
        result = subprocess.run(cmd, cwd=str(repo_root), timeout=BUILD_TIMEOUT)
        if result.returncode != 0:
            print("Error: Build failed", file=sys.stderr)
            return result.returncode

        if push and not local:
            print(f"Pushing {full_tag}...")
            push_result = subprocess.run(
                ["docker", "push", full_tag], timeout=PUSH_TIMEOUT
            )
            if push_result.returncode != 0:
                print(f"Error: Push failed for {full_tag}", file=sys.stderr)
                return push_result.returncode

        return 0

    except Exception as e:
        print(f"Error during build: {e}", file=sys.stderr)
        return 1


def cmd_build(args: argparse.Namespace) -> int:
    """
    Main handler for `jmo build` command.

    Builds the JMo Security Docker image.
    """
    build_cmd = getattr(args, "build_command", None)

    # Docker is checked before the repository, but `build validate` only runs
    # `update_versions.py --validate` -- it never touches Docker. Requiring a
    # daemon for it made the one subcommand that works offline refuse to run,
    # and is why `jmo validate --tier full` could only ever SKIP it.
    if build_cmd != "validate" and not _check_docker():
        return 1

    # Find repository root
    repo_root = _find_repo_root()
    if not repo_root:
        print(
            "Error: Cannot find repository root "
            f"(looking for versions.yaml and {DOCKERFILE})",
            file=sys.stderr,
        )
        print(
            "Run this command from within the jmo-security repository", file=sys.stderr
        )
        return 1

    print(f"Repository root: {repo_root}")

    if build_cmd == "validate":
        # Just validate versions
        if _validate_versions(repo_root):
            print("Validation passed")
            return 0
        return 1

    if build_cmd == "test":
        # Test a built image
        image = _image_ref(
            args.tag,
            args.registry,
            args.org,
            DEFAULT_IMAGE,
            args.local,
        )

        print(f"Testing image: {image}")
        cmds = [
            ["docker", "run", "--rm", image, "--version"],
            ["docker", "run", "--rm", image, "--help"],
        ]
        for cmd in cmds:
            print(f"  Running: {' '.join(cmd)}")
            try:
                result = subprocess.run(cmd, timeout=RUN_TIMEOUT)
            except subprocess.TimeoutExpired:
                print(
                    f"Test timed out after {RUN_TIMEOUT}s: {' '.join(cmd)}",
                    file=sys.stderr,
                )
                return 1
            if result.returncode != 0:
                print(f"Test failed: {' '.join(cmd)}", file=sys.stderr)
                return 1
        print("All tests passed")
        return 0

    # Default: build
    # Validate versions first (unless skipped)
    if not args.skip_validate:
        if not _validate_versions(repo_root):
            print("Build aborted due to validation failure", file=sys.stderr)
            print("Use --skip-validate to bypass version checking", file=sys.stderr)
            return 1

    build_result = _build_image(
        tag=args.tag,
        repo_root=repo_root,
        registry=args.registry,
        org=args.org,
        image_name=DEFAULT_IMAGE,
        local=args.local,
        no_cache=args.no_cache,
        push=args.push,
        platform_target=args.platform,
    )
    if build_result != 0:
        return build_result

    print("Image built successfully")
    if args.local:
        local_ref = _image_ref(args.tag, args.registry, args.org, DEFAULT_IMAGE, True)
        print(f"\nTest with: docker run --rm {local_ref} --help")

    return 0


def add_build_args(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    """Add 'build' subcommand arguments."""
    build_parser: argparse.ArgumentParser = subparsers.add_parser(
        "build",
        help="Build the JMo Security Docker image",
        description="""
Build the JMo Security Docker image from Dockerfile.

Replaces Makefile docker-* targets with unified CLI commands. The image carries
every scanner in the tool matrix plus the policy engine (see docs/TOOLS.md).

Examples:
  jmo build                           # Build, tagged ghcr.io/jimmy058910/jmo-security:latest
  jmo build --local                   # Build with the local-only tag jmo-security:local
  jmo build --push --tag 2.0.0        # Build and push to the registry
  jmo build validate                  # Validate versions before building
  jmo build test --local              # Test a locally built image

Pre-build Validation:
  By default, `jmo build` validates that all tool versions in versions.yaml
  exist upstream (GitHub releases, PyPI) before starting the build.
  Use --skip-validate to bypass this check.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands
    build_subparsers = build_parser.add_subparsers(dest="build_command")

    # VALIDATE subcommand
    build_subparsers.add_parser(
        "validate",
        help="Validate tool versions exist upstream (GitHub, PyPI). Set GITHUB_TOKEN env var to avoid API rate limiting",
    )

    # TEST subcommand.
    #
    # Every flag here is also declared on the parent `build` parser. argparse
    # applies a subparser's defaults *after* the parent has already parsed, so a
    # subparser default overwrites a value the user gave the parent: measured,
    # `jmo build --variant deep test` (a flag since removed) produced
    # `variant='balanced'` -- rc 0, no warning, the wrong image tested.
    # `default=SUPPRESS` leaves the attribute untouched when the flag is absent,
    # so the parent's value survives and an explicit `jmo build test --tag X`
    # still wins.
    test_parser = build_subparsers.add_parser(
        "test",
        help="Test a built Docker image",
    )
    test_parser.add_argument(
        "--local",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Test the local-tagged image",
    )
    test_parser.add_argument(
        "--registry",
        default=argparse.SUPPRESS,
        help=f"Docker registry (default: {DEFAULT_REGISTRY})",
    )
    test_parser.add_argument(
        "--org",
        default=argparse.SUPPRESS,
        help=f"Docker organization (default: {DEFAULT_ORG})",
    )
    test_parser.add_argument(
        "--tag",
        default=argparse.SUPPRESS,
        help="Image tag (default: latest)",
    )

    # Main build arguments
    build_parser.add_argument(
        "--local",
        action="store_true",
        help="Use the local tag (jmo-security:local) for testing",
    )
    build_parser.add_argument(
        "--tag",
        default="latest",
        help="Image tag (default: latest)",
    )
    build_parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help=f"Docker registry (default: {DEFAULT_REGISTRY})",
    )
    build_parser.add_argument(
        "--org",
        default=DEFAULT_ORG,
        help=f"Docker organization (default: {DEFAULT_ORG})",
    )
    build_parser.add_argument(
        "--push",
        action="store_true",
        help="Push the image to the registry after building",
    )
    build_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Build without using cache",
    )
    build_parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip version validation before building",
    )
    build_parser.add_argument(
        "--platform",
        choices=["amd64", "arm64"],
        help="Target platform (default: auto-detect)",
    )

    return build_parser
