"""
CLI command handlers for `jmo build`.

Provides Docker image building functionality, replacing Makefile docker-* targets.
Supports all 4 variants: fast, slim, balanced, deep (full).
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Variant configuration: maps variant name to Dockerfile
VARIANTS = {
    "fast": "Dockerfile.fast",
    "slim": "Dockerfile.slim",
    "balanced": "Dockerfile.balanced",
    "deep": "Dockerfile",  # Base Dockerfile is the full/deep variant
}

# Default registry configuration
DEFAULT_REGISTRY = "ghcr.io"
DEFAULT_ORG = "jmosecurity"
DEFAULT_IMAGE = "jmo-security"


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
    if not shutil.which("docker"):
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


def _find_repo_root() -> Optional[Path]:
    """Find the repository root (directory containing Dockerfile)."""
    # Start from current directory and walk up
    current = Path.cwd()
    for parent in [current] + list(current.parents):
        if (parent / "Dockerfile").exists() and (parent / "versions.yaml").exists():
            return parent
    return None


def _validate_versions(repo_root: Path) -> bool:
    """
    Validate that all versions in versions.yaml exist upstream.

    Returns True if validation passes or is skipped, False on failure.
    """
    validate_script = repo_root / "scripts" / "dev" / "update_versions.py"
    if not validate_script.exists():
        print("Warning: Version validation script not found, skipping validation")
        return True

    print("Validating tool versions...")
    try:
        result = subprocess.run(
            [sys.executable, str(validate_script), "--validate"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
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
        print("Warning: Version validation timed out, proceeding anyway")
        return True
    except Exception as e:
        print(f"Warning: Version validation error: {e}, proceeding anyway")
        return True


def _build_image(
    variant: str,
    tag: str,
    repo_root: Path,
    registry: str,
    org: str,
    image_name: str,
    local: bool = False,
    no_cache: bool = False,
    push: bool = False,
    platform_target: Optional[str] = None,
) -> int:
    """Build a single Docker image variant."""
    dockerfile = VARIANTS.get(variant)
    if not dockerfile:
        print(f"Error: Unknown variant '{variant}'", file=sys.stderr)
        print(f"Available variants: {', '.join(VARIANTS.keys())}", file=sys.stderr)
        return 1

    dockerfile_path = repo_root / dockerfile
    if not dockerfile_path.exists():
        print(f"Error: Dockerfile not found: {dockerfile_path}", file=sys.stderr)
        return 1

    # Determine image tag
    if local:
        full_tag = f"{image_name}:local-{variant}"
    else:
        full_tag = f"{registry}/{org}/{image_name}:{tag}-{variant}"

    # Detect architecture
    arch = platform_target or _detect_arch()

    print(f"Building {variant} variant...")
    print(f"  Dockerfile: {dockerfile}")
    print(f"  Tag: {full_tag}")
    print(f"  Architecture: {arch}")

    # Build command
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
        result = subprocess.run(cmd, cwd=str(repo_root))
        if result.returncode != 0:
            print(f"Error: Build failed for {variant}", file=sys.stderr)
            return result.returncode

        # Tag as latest if this is the deep/full variant
        if variant == "deep" and not local:
            latest_tag = f"{registry}/{org}/{image_name}:{tag}"
            subprocess.run(["docker", "tag", full_tag, latest_tag])
            print(f"  Also tagged as: {latest_tag}")

        # Push if requested
        if push and not local:
            print(f"Pushing {full_tag}...")
            push_result = subprocess.run(["docker", "push", full_tag])
            if push_result.returncode != 0:
                print(f"Error: Push failed for {full_tag}", file=sys.stderr)
                return push_result.returncode

            if variant == "deep":
                latest_tag = f"{registry}/{org}/{image_name}:{tag}"
                subprocess.run(["docker", "push", latest_tag])

        return 0

    except Exception as e:
        print(f"Error during build: {e}", file=sys.stderr)
        return 1


def cmd_build(args: argparse.Namespace) -> int:
    """
    Main handler for `jmo build` command.

    Builds Docker images for JMo Security suite.
    """
    # Check Docker availability
    if not _check_docker():
        return 1

    # Find repository root
    repo_root = _find_repo_root()
    if not repo_root:
        print(
            "Error: Cannot find repository root (looking for Dockerfile and versions.yaml)",
            file=sys.stderr,
        )
        print("Run this command from within the jmo-security repository", file=sys.stderr)
        return 1

    print(f"Repository root: {repo_root}")

    # Handle subcommands
    build_cmd = getattr(args, "build_command", None)

    if build_cmd == "validate":
        # Just validate versions
        if _validate_versions(repo_root):
            print("Validation passed")
            return 0
        return 1

    if build_cmd == "test":
        # Test a built image
        variant = args.variant
        local = args.local
        if local:
            image = f"{DEFAULT_IMAGE}:local-{variant}"
        else:
            image = f"{args.registry}/{args.org}/{DEFAULT_IMAGE}:{args.tag}-{variant}"

        print(f"Testing image: {image}")
        cmds = [
            ["docker", "run", "--rm", image, "--version"],
            ["docker", "run", "--rm", image, "--help"],
        ]
        for cmd in cmds:
            print(f"  Running: {' '.join(cmd)}")
            result = subprocess.run(cmd)
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

    # Determine which variants to build
    if args.all:
        variants = list(VARIANTS.keys())
    else:
        variants = [args.variant]

    # Build each variant
    failed = []
    for variant in variants:
        print(f"\n{'='*60}")
        print(f"Building variant: {variant}")
        print(f"{'='*60}\n")

        result = _build_image(
            variant=variant,
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

        if result != 0:
            failed.append(variant)

    # Summary
    print(f"\n{'='*60}")
    print("Build Summary")
    print(f"{'='*60}")

    if failed:
        print(f"Failed: {', '.join(failed)}")
        print(f"Succeeded: {', '.join(v for v in variants if v not in failed)}")
        return 1

    print(f"All {len(variants)} variant(s) built successfully")

    if args.local:
        print("\nLocal images created:")
        for v in variants:
            print(f"  - {DEFAULT_IMAGE}:local-{v}")
        print(f"\nTest with: docker run --rm {DEFAULT_IMAGE}:local-{variants[0]} --help")

    return 0


def add_build_args(subparsers) -> argparse.ArgumentParser:
    """Add 'build' subcommand arguments."""
    build_parser = subparsers.add_parser(
        "build",
        help="Build Docker images for JMo Security",
        description="""
Build Docker images for JMo Security suite.

Replaces Makefile docker-* targets with unified CLI commands.

Variants:
  fast      8 tools, ~502 MB  - CI/CD, pre-commit hooks
  slim      14 tools, ~557 MB - Cloud/IaC focused
  balanced  18 tools, ~1.4 GB - Production scans (DEFAULT)
  deep      28 tools, ~2.0 GB - Comprehensive audits

Examples:
  jmo build                           # Build balanced variant (local)
  jmo build --variant deep            # Build deep/full variant
  jmo build --all --local             # Build all variants with local tags
  jmo build --push --tag v1.0.0       # Build and push to registry
  jmo build validate                  # Validate versions before building
  jmo build test --variant balanced   # Test a built image

Pre-build Validation:
  By default, `jmo build` validates that all tool versions in versions.yaml
  exist upstream (GitHub releases, PyPI, npm) before starting the build.
  Use --skip-validate to bypass this check.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands
    build_subparsers = build_parser.add_subparsers(dest="build_command")

    # VALIDATE subcommand
    build_subparsers.add_parser(
        "validate",
        help="Validate tool versions exist upstream (GitHub, PyPI, npm)",
    )

    # TEST subcommand
    test_parser = build_subparsers.add_parser(
        "test",
        help="Test a built Docker image",
    )
    test_parser.add_argument(
        "--variant",
        choices=list(VARIANTS.keys()),
        default="balanced",
        help="Variant to test (default: balanced)",
    )
    test_parser.add_argument(
        "--local",
        action="store_true",
        help="Test local-tagged image",
    )
    test_parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help=f"Docker registry (default: {DEFAULT_REGISTRY})",
    )
    test_parser.add_argument(
        "--org",
        default=DEFAULT_ORG,
        help=f"Docker organization (default: {DEFAULT_ORG})",
    )
    test_parser.add_argument(
        "--tag",
        default="latest",
        help="Image tag (default: latest)",
    )

    # Main build arguments
    build_parser.add_argument(
        "--variant",
        choices=list(VARIANTS.keys()),
        default="balanced",
        help="Docker variant to build (default: balanced)",
    )
    build_parser.add_argument(
        "--all",
        action="store_true",
        help="Build all variants (fast, slim, balanced, deep)",
    )
    build_parser.add_argument(
        "--local",
        action="store_true",
        help="Use local tags (jmo-security:local-<variant>) for testing",
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
        help="Push images to registry after building",
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
