"""
Repository Scanner

Scans local Git repositories using multiple security tools.

Fully Implemented Tools (26 total):

Core Tools (11):
1. TruffleHog: Verified secrets scanning
2. Nosey Parker: Deep secrets detection (multi-phase: init/scan/report, Docker fallback)
3. Semgrep: Static analysis (SAST)
4. Bandit: Python security analysis
5. Syft: SBOM generation
6. Trivy: Vulnerability and secrets scanning
7. Checkov: IaC policy checks
8. Hadolint: Dockerfile linting
9. ZAP: Web vulnerability scanning (limited to repos with HTML/JS/PHP files)
10. Falco: Runtime security monitoring (validates Falco rule files)
11. AFL++: Coverage-guided fuzzing (analyzes compiled binaries)

v1.0.0 New Tools (15):
12. Checkov CI/CD: GitHub Actions workflow security
13. Gosec: Go security analyzer
14. cdxgen: SBOM and dependency analysis
15. ScanCode: License and copyright scanner
16. Kubescape: Kubernetes security scanner
17. Prowler: Multi-cloud CSPM (AWS/Azure/GCP/K8s)
18. YARA: Malware detection
19. Grype: Vulnerability scanner for containers/filesystems
20. MobSF: Mobile Security Framework (Android/iOS)
21. Lynis: System hardening and security auditing
22. Trivy RBAC: Kubernetes RBAC security assessment
23. Semgrep Secrets: Hardcoded credentials detection
24. Horusec: Multi-language SAST (18+ languages)
25. Dependency-Check: OWASP SCA for known vulnerabilities
26. Akto: API Security testing (URL scanner only)

Special Tool Behaviors:
- Nosey Parker: Multi-phase execution (init → scan → report) with automatic Docker fallback
- ZAP: Scans static web files when present; writes stub if no web files found
- Falco: Validates Falco rule files when present; writes stub if no rules found
- AFL++: Fuzzes binaries when found; writes stub if no fuzzable binaries found
- Prowler: Only runs if cloud config files (*.tf, *.tfvars, cloudformation.yaml) detected
- MobSF: Only runs if mobile app files (*.apk, *.ipa) detected
- Lynis: System-level scanner - writes stub for repository scans
- Trivy RBAC: Only runs if Kubernetes manifests detected
- Akto: Only available in URL scanner (requires live API endpoints)

Integrates with ToolRunner for parallel execution and resilient error handling.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

from ...core.config import RetryConfig
from ...core.paths import get_yara_rules_dir
from ...core.scan_timings import write_scan_timings
from ...core.tool_runner import ToolDefinition, ToolRunner
from ..path_sanitizers import _sanitize_path_component, _validate_output_path
from ..scan_utils import (
    TOOL_TIMEOUT_DEFAULTS,
    find_tool,
    report_tool_failure,
    tool_flags,
    tool_timeout,
    write_stub,
)

logger = logging.getLogger(__name__)

# TOOL_TIMEOUT_DEFAULTS now lives in scan_utils and is re-exported here for the
# handful of readers that reach for it by this name. It was defined in this
# module, which is exactly why only *repository* scans honoured the floor: the
# other four scanners could not see it and their `get_tool_timeout` copies had
# none. `zap` carries a 900 s floor and also runs on `url` targets, so a
# `balanced` URL scan gave it 600 s -- a third short -- while the same tool on a
# repository target got 900 s.
__all__ = ["TOOL_TIMEOUT_DEFAULTS", "scan_repository"]

# Upper bound on file arguments passed to a single per-file tool invocation.
# Windows caps a command line at 32767 characters; a few hundred absolute paths
# stays well inside that while covering every repository we have measured
# (docker-library/postgres, the densest, has 55 shell scripts and 26
# Dockerfiles). Exceeding it is reported, never silently truncated - a cap that
# does not announce itself reads as "everything was scanned" when it was not.
MAX_FILE_ARGS = 300


def _collect_files(repo: Path, patterns: tuple[str, ...], tool_name: str) -> list[str]:
    """Collect matching files for a tool that takes file arguments.

    Both shellcheck and hadolint accept many paths per invocation; scanning one
    file and calling it done under-reports without saying so. hadolint used to
    take `dockerfiles[0]`, which on docker-library/postgres meant 1 of 26 files
    (and 1 of 14 on kubernetes-goat) - about 90% of Dockerfiles unexamined,
    with nothing in the output to indicate it.
    """
    seen: set[Path] = set()
    for pattern in patterns:
        for path in repo.glob(pattern):
            # Repositories vendor dependencies; scanning node_modules or a
            # bundled venv buries the repo's own findings in third-party noise.
            parts = set(path.parts)
            if parts & {".git", "node_modules", "vendor", ".venv", "venv"}:
                continue
            if path.is_file():
                seen.add(path)

    files = sorted(seen)
    if len(files) > MAX_FILE_ARGS:
        logger.warning(
            "%s: %d matching files in %s, scanning the first %d "
            "(command-line length limit) - %d file(s) NOT scanned",
            tool_name,
            len(files),
            repo.name,
            MAX_FILE_ARGS,
            len(files) - MAX_FILE_ARGS,
        )
        files = files[:MAX_FILE_ARGS]

    return [str(f) for f in files]


def scan_repository(
    repo: Path,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    tool_exists_func: Callable[[str], bool] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
    find_tool_func: Callable[[str], str | None] | None = None,
    progress_callback: Callable[[str, str, int], None] | None = None,
) -> tuple[str, dict[str, bool]]:
    """
    Scan a Git repository with multiple security tools.

    Args:
        repo: Path to Git repository to scan
        results_dir: Base results directory (individual-repos)
        tools: List of tools to run
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check if tool exists (for testing)
        write_stub_func: Optional function to write stub files (for testing)
        find_tool_func: Optional function to find tool path (for testing)
        progress_callback: Optional callback(tool_name, status, findings_count)
                          Called when tools start and complete for progress tracking

    Returns:
        Tuple of (repo_name, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    statuses: dict[str, bool] = {}
    tool_defs = []

    # Use provided functions or defaults
    _write_stub = write_stub_func or write_stub
    _resolve_tool = find_tool_func or find_tool

    # Every tool block below is `if X in tools: path = _find_tool(X)` followed by
    # `if path: ... elif allow_missing_tools: ...`. When neither holds the tool is
    # dropped with no status, no warning and no error -- the scan simply runs
    # without it and still exits 0. That is how checkov vanished from a repo with
    # 47 Terraform files while `jmo tools check` reported it OK.
    #
    # Recording here rather than in all 26 blocks: they share this one alias.
    unresolved: list[str] = []

    # Tools this scanner actually has a code path for. Only an implemented block
    # reaches `_find_tool`, so membership is recorded rather than inferred.
    # Inferring it from "produced no ToolDefinition" cannot distinguish "no
    # implementation" from "implemented, but this repo has no matching files" -
    # and reporting the wrong reason sends the reader hunting for code that
    # already exists.
    considered: set[str] = set()

    # For a lookup made on behalf of a profile tool, the binary that was
    # actually missing - so the report can name both.
    missing_dependency: dict[str, str] = {}

    def _find_tool(tool_name: str, record_as: str | None = None) -> str | None:
        """Resolve a binary, recorded against the profile tool that needs it.

        `record_as` matters because several blocks resolve a binary that is not
        the tool the user asked for: checkov-cicd runs `checkov`, trivy-rbac
        runs `trivy`, semgrep-secrets runs `semgrep`, zap runs `zap-baseline.py`
        plus `docker`, afl++ runs `afl-fuzz`.

        Without it, `considered` only ever learned the binary names, so
        `not_implemented` (`set(tools) - considered`) accused tools that had
        demonstrably run - a deep scan of terragoat reported checkov-cicd,
        semgrep-secrets and trivy-rbac as having "no repository implementation"
        in the same run that wrote all three of their output files. In the other
        direction, `unresolved` reported `docker` and `zap-baseline.py` as tools
        whose findings were missing, and neither is a tool in any profile.
        """
        owner = record_as or tool_name
        considered.add(owner)
        resolved = _resolve_tool(tool_name)
        if resolved is None:
            unresolved.append(owner)
            if owner != tool_name:
                missing_dependency[owner] = tool_name
        return resolved

    name = _sanitize_path_component(repo.name)
    out_dir = results_dir / name
    _validate_output_path(results_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def get_tool_timeout(tool: str, default: int) -> int:
        """Timeout for this tool, honouring the slow-tool floor.

        Priority: an explicit `per_tool.<tool>.timeout` wins outright, else the
        profile default raised to `TOOL_TIMEOUT_DEFAULTS` if the tool has a
        floor. Slow tools (cdxgen, dependency-check, scancode) have minimums so
        a low profile default cannot kill them early.

        Delegates to the shared implementation. This body was the only one of
        five that applied the floor at all.
        """
        return tool_timeout(per_tool_config, tool, default)

    def get_tool_flags(tool: str) -> list[str]:
        """Extra flags for this tool, minus any JMo must own.

        Delegates to the shared implementation: this was one of five identical
        copies, none of which filtered anything, so a `per_tool` flag could
        override JMo's own `-f`/`-o` and silently destroy the tool's findings
        (#822).
        """
        return tool_flags(per_tool_config, tool)

    # TruffleHog: Verified secrets scanning
    # Uses filesystem mode to scan working directory (not just git history)
    # This catches secrets that may not be committed yet or in non-git directories
    if "trufflehog" in tools:
        trufflehog_out = out_dir / "trufflehog.json"
        trufflehog_path = _find_tool("trufflehog")
        if trufflehog_path:
            trufflehog_flags = get_tool_flags("trufflehog")
            trufflehog_cmd = [
                trufflehog_path,
                "filesystem",
                str(repo),
                "--json",
                "--no-update",
                *trufflehog_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trufflehog",
                    command=trufflehog_cmd,
                    output_file=trufflehog_out,
                    timeout=get_tool_timeout("trufflehog", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("trufflehog", trufflehog_out)
            statuses["trufflehog"] = True

    # Semgrep: Static analysis
    if "semgrep" in tools:
        semgrep_out = out_dir / "semgrep.json"
        semgrep_path = _find_tool("semgrep")
        if semgrep_path:
            semgrep_flags = get_tool_flags("semgrep")

            # Get semgrep configs from per_tool_config (allows offline mode)
            # Default: ["auto"] - uses Semgrep Registry auto-detection
            # Custom: ["p/python", "p/javascript"] - specify language packs
            # Note: "p/security" ruleset was deprecated, use "auto" instead
            semgrep_tool_config = per_tool_config.get("semgrep", {})
            if isinstance(semgrep_tool_config, dict):
                semgrep_configs = semgrep_tool_config.get("configs", ["auto"])
            else:
                semgrep_configs = ["auto"]

            # Build config arguments
            config_args = []
            for cfg in semgrep_configs:
                config_args.extend(["--config", cfg])

            semgrep_cmd = [
                semgrep_path,
                *config_args,
                "--json",
                "--output",
                str(semgrep_out),
                *semgrep_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="semgrep",
                    command=semgrep_cmd,
                    output_file=semgrep_out,
                    timeout=get_tool_timeout("semgrep", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 2),  # 0=clean, 1=findings, 2=errors
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("semgrep", semgrep_out)
            statuses["semgrep"] = True

    # Trivy: Vulnerability and secrets scanning
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        trivy_path = _find_tool("trivy")
        if trivy_path:
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                trivy_path,
                "fs",
                "-q",
                "-f",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                *trivy_flags,
                str(repo),
                "-o",
                str(trivy_out),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trivy",
                    command=trivy_cmd,
                    output_file=trivy_out,
                    timeout=get_tool_timeout("trivy", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("trivy", trivy_out)
            statuses["trivy"] = True

    # Syft: SBOM generation
    if "syft" in tools:
        syft_out = out_dir / "syft.json"
        syft_path = _find_tool("syft")
        if syft_path:
            syft_flags = get_tool_flags("syft")
            syft_cmd = [
                syft_path,
                f"dir:{repo}",
                "-o",
                "json",
                *syft_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="syft",
                    command=syft_cmd,
                    output_file=syft_out,
                    timeout=get_tool_timeout("syft", timeout),
                    retries=retries,
                    ok_return_codes=(0,),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("syft", syft_out)
            statuses["syft"] = True

    # Checkov: IaC policy checks
    if "checkov" in tools:
        checkov_out = out_dir / "checkov.json"
        checkov_path = _find_tool("checkov")
        if checkov_path:
            checkov_flags = get_tool_flags("checkov")
            checkov_cmd = [
                checkov_path,
                "-d",
                str(repo),
                "-o",
                "json",
                *checkov_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="checkov",
                    command=checkov_cmd,
                    output_file=checkov_out,
                    timeout=get_tool_timeout("checkov", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("checkov", checkov_out)
            statuses["checkov"] = True

    # Hadolint: Dockerfile linting
    if "hadolint" in tools:
        hadolint_out = out_dir / "hadolint.json"
        hadolint_path = _find_tool("hadolint")
        if hadolint_path:
            hadolint_flags = get_tool_flags("hadolint")

            # hadolint's usage is `[DOCKERFILE...]` - it takes as many paths as
            # you give it. This previously passed `dockerfiles[0]` only, so
            # docker-library/postgres had 1 of its 26 Dockerfiles scanned and
            # kubernetes-goat 1 of 14 - ~90% unexamined, silently.
            dockerfiles = _collect_files(
                repo,
                ("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"),
                "hadolint",
            )
            if dockerfiles:
                hadolint_cmd = [
                    hadolint_path,
                    "-f",
                    "json",
                    *hadolint_flags,
                    *dockerfiles,
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="hadolint",
                        command=hadolint_cmd,
                        output_file=hadolint_out,
                        timeout=get_tool_timeout("hadolint", timeout),
                        retries=retries,
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
        elif allow_missing_tools:
            _write_stub("hadolint", hadolint_out)
            statuses["hadolint"] = True

    # ShellCheck: shell script static analysis
    #
    # shellcheck ships in PROFILE_TOOLS["fast"], installs cleanly and reports OK
    # from `jmo tools check`, but had no repository implementation at all - so it
    # could never run, and `shellcheck_adapter.py` sat waiting for input that was
    # never produced. Measured: docker-library/postgres has 55 shell scripts and
    # kubernetes-goat 7, none of them examined.
    #
    # Shell scripts are a genuine finding source in public repositories:
    # unquoted expansions (SC2086), unquoted command substitution (SC2046) and
    # `cd` without a failure guard (SC2164) are command-injection and
    # data-destruction risks, not merely style.
    if "shellcheck" in tools:
        shellcheck_out = out_dir / "shellcheck.json"
        shellcheck_path = _find_tool("shellcheck")
        if shellcheck_path:
            shellcheck_flags = get_tool_flags("shellcheck")
            shell_scripts = _collect_files(
                repo, ("**/*.sh", "**/*.bash", "**/*.ksh"), "shellcheck"
            )
            if shell_scripts:
                shellcheck_cmd = [
                    shellcheck_path,
                    "--format=json",
                    *shellcheck_flags,
                    *shell_scripts,
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="shellcheck",
                        command=shellcheck_cmd,
                        output_file=shellcheck_out,
                        timeout=get_tool_timeout("shellcheck", timeout),
                        retries=retries,
                        # 0 = clean, 1 = findings. 2+ are fatal parse/usage
                        # errors and must NOT be graded acceptable.
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
        elif allow_missing_tools:
            _write_stub("shellcheck", shellcheck_out)
            statuses["shellcheck"] = True

    # Bandit: Python security analysis
    if "bandit" in tools:
        bandit_out = out_dir / "bandit.json"
        bandit_path = _find_tool("bandit")
        if bandit_path:
            bandit_flags = get_tool_flags("bandit")
            bandit_cmd = [
                bandit_path,
                "-r",
                str(repo),
                "-f",
                "json",
                "-o",
                str(bandit_out),
                *bandit_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="bandit",
                    command=bandit_cmd,
                    output_file=bandit_out,
                    timeout=get_tool_timeout("bandit", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("bandit", bandit_out)
            statuses["bandit"] = True

    # Nosey Parker: Deep secrets detection with Docker fallback
    if "noseyparker" in tools:
        noseyparker_out = out_dir / "noseyparker.json"
        noseyparker_flags = get_tool_flags("noseyparker")

        # Strategy 1: Try local noseyparker binary (two-phase: scan + report)
        noseyparker_path = _find_tool("noseyparker")
        if noseyparker_path:
            # Nosey Parker requires a datastore directory
            datastore_dir = out_dir / ".noseyparker_datastore"
            datastore_dir.mkdir(parents=True, exist_ok=True)

            # Phase 1: Initialize datastore (idempotent)
            init_cmd = [
                noseyparker_path,
                "datastore",
                "init",
                "--datastore",
                str(datastore_dir),
            ]
            # Phase 2: Scan repository
            scan_cmd = [
                noseyparker_path,
                "scan",
                "--datastore",
                str(datastore_dir),
                str(repo),
                *noseyparker_flags,
            ]
            # Phase 3: Generate JSON report
            report_cmd = [
                noseyparker_path,
                "report",
                "--format",
                "json",
                "--datastore",
                str(datastore_dir),
            ]

            # Multi-phase execution using ToolRunner (3 sequential commands)
            tool_defs.append(
                ToolDefinition(
                    name="noseyparker-init",
                    command=init_cmd,
                    output_file=None,  # No output file for init
                    timeout=60,  # Quick init
                    retries=0,
                    ok_return_codes=(0,),
                    capture_stdout=False,
                )
            )
            tool_defs.append(
                ToolDefinition(
                    name="noseyparker-scan",
                    command=scan_cmd,
                    output_file=None,  # Scan writes to datastore
                    timeout=get_tool_timeout("noseyparker", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),  # 0=clean, 1=findings
                    capture_stdout=False,
                )
            )
            tool_defs.append(
                ToolDefinition(
                    name="noseyparker-report",
                    command=report_cmd,
                    output_file=noseyparker_out,
                    timeout=120,  # Report generation should be fast
                    retries=0,
                    ok_return_codes=(0,),
                    capture_stdout=True,  # Capture JSON output
                )
            )
        # Strategy 2: Fallback to Docker-based noseyparker
        else:
            docker_np_path = _find_tool("docker", record_as="noseyparker")
            noseyparker_docker_script = (
                Path(__file__).parent.parent.parent / "core/run_noseyparker_docker.sh"
            )
            if docker_np_path and noseyparker_docker_script.exists():
                docker_cmd = [
                    "bash",
                    str(noseyparker_docker_script),
                    "--repo",
                    str(repo),
                    "--out",
                    str(noseyparker_out),
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="noseyparker",
                        command=docker_cmd,
                        output_file=noseyparker_out,
                        timeout=get_tool_timeout("noseyparker", timeout),
                        retries=retries,
                        ok_return_codes=(0,),
                        capture_stdout=False,  # Script writes file directly
                    )
                )
            elif allow_missing_tools:
                _write_stub("noseyparker", noseyparker_out)
                statuses["noseyparker"] = True

    # ZAP: Web vulnerability scanning (limited to repositories with web servers)
    # Note: ZAP is best suited for live URLs (see url_scanner.py).
    # For repositories, we scan for common web vulnerabilities in static files.
    if "zap" in tools:
        zap_out = out_dir / "zap.json"
        # ZAP baseline scan can analyze HTML/JS files in repository
        # This is a limited use case; full DAST requires --url target
        zap_baseline_path = _find_tool("zap-baseline.py", record_as="zap")
        zap_docker_path = _find_tool("docker", record_as="zap")
        if zap_baseline_path or zap_docker_path:
            zap_flags = get_tool_flags("zap")
            # Check for web-related files (HTML, JS, PHP, etc.)
            web_files = (
                list(repo.glob("**/*.html"))
                + list(repo.glob("**/*.js"))
                + list(repo.glob("**/*.php"))
            )
            if web_files:
                # Use ZAP baseline scan on first web file found
                # Note: This is a simplified approach; full ZAP requires live server
                target_file = web_files[0]
                if zap_baseline_path:
                    zap_cmd = [
                        zap_baseline_path,  # Use full path from find_tool
                        "-t",
                        str(target_file),
                        "-J",
                        str(zap_out),
                        *zap_flags,
                    ]
                    tool_defs.append(
                        ToolDefinition(
                            name="zap",
                            command=zap_cmd,
                            output_file=zap_out,
                            timeout=get_tool_timeout("zap", timeout),
                            retries=retries,
                            ok_return_codes=(
                                0,
                                1,
                                2,
                            ),  # ZAP returns non-zero on findings
                            capture_stdout=False,
                        )
                    )
                else:
                    docker_path = _find_tool("docker")
                    if docker_path:
                        # Fallback to Docker-based ZAP
                        zap_cmd = [
                            docker_path,
                            "run",
                            "--rm",
                            "-v",
                            f"{repo}:/zap/wrk:ro",
                            "ghcr.io/zaproxy/zaproxy:stable",
                            "zap-baseline.py",
                            "-t",
                            f"/zap/wrk/{target_file.relative_to(repo)}",
                            "-J",
                            "/zap/wrk/zap-output.json",
                            *zap_flags,
                        ]
                        tool_defs.append(
                            ToolDefinition(
                                name="zap",
                                command=zap_cmd,
                                output_file=zap_out,
                                timeout=get_tool_timeout("zap", timeout),
                                retries=retries,
                                ok_return_codes=(0, 1, 2),
                                capture_stdout=False,
                            )
                        )
            else:
                # No web files found - write empty stub
                _write_stub("zap", zap_out)
                statuses["zap"] = True
        elif allow_missing_tools:
            _write_stub("zap", zap_out)
            statuses["zap"] = True

    # Falco: Runtime security monitoring (repository rules analysis)
    # Note: Falco is best suited for live containers/K8s (see k8s_scanner.py).
    # For repositories, we check for Falco rule files and validate them.
    if "falco" in tools:
        falco_out = out_dir / "falco.json"
        falco_path = _find_tool("falco")
        if falco_path:
            falco_flags = get_tool_flags("falco")
            # Look for Falco rule files in repository
            falco_rules = list(repo.glob("**/*falco*.yaml")) + list(
                repo.glob("**/*falco*.yml")
            )
            if falco_rules:
                # Validate Falco rules using falco --validate
                rules_file = falco_rules[0]
                falco_cmd = [
                    falco_path,
                    "--validate",
                    str(rules_file),
                    "--output-json",
                    *falco_flags,
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="falco",
                        command=falco_cmd,
                        output_file=falco_out,
                        timeout=get_tool_timeout("falco", timeout),
                        retries=retries,
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
            else:
                # No Falco rules found - write empty stub
                _write_stub("falco", falco_out)
                statuses["falco"] = True
        elif allow_missing_tools:
            _write_stub("falco", falco_out)
            statuses["falco"] = True

    # AFL++: Coverage-guided fuzzing (repository binary analysis)
    # Note: AFL++ requires instrumented binaries and fuzzing harness.
    # For repositories, we check for compiled binaries and run basic fuzz testing.
    if "afl++" in tools:
        afl_out = out_dir / "aflplusplus.json"
        afl_fuzz_path = _find_tool("afl-fuzz", record_as="afl++")
        afl_analyze_path = _find_tool("afl-analyze", record_as="afl++")
        if afl_fuzz_path or afl_analyze_path:
            afl_flags = get_tool_flags("afl++")
            # Look for compiled binaries or fuzzing harnesses
            binaries = []
            for pattern in ["**/*-afl", "**/*-fuzzer", "**/bin/*", "**/build/*"]:
                found = [
                    f
                    for f in repo.glob(pattern)
                    if f.is_file() and f.stat().st_mode & 0o111
                ]
                binaries.extend(found)

            if binaries and afl_analyze_path:
                # Run afl-analyze on the first binary found
                binary = binaries[0]
                # Create minimal input corpus
                corpus_dir = out_dir / ".afl_corpus"
                corpus_dir.mkdir(parents=True, exist_ok=True)
                (corpus_dir / "test1").write_bytes(b"test")

                # Run AFL++ dry run (no actual fuzzing, just validation)
                afl_cmd = [
                    afl_fuzz_path or afl_analyze_path,
                    "-i",
                    str(corpus_dir),
                    "-o",
                    str(out_dir / ".afl_output"),
                    "-V",
                    "10",  # 10-second timeout
                    "-m",
                    "none",  # No memory limit
                    *afl_flags,
                    "--",
                    str(binary),
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="afl++",
                        command=afl_cmd,
                        output_file=afl_out,
                        timeout=get_tool_timeout("afl++", timeout),
                        retries=0,  # Fuzzing is deterministic, no retries
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
            else:
                # No fuzzable binaries found - write empty stub
                _write_stub("afl++", afl_out)
                statuses["afl++"] = True
        elif allow_missing_tools:
            _write_stub("afl++", afl_out)
            statuses["afl++"] = True

    # ========== v1.0.0 New Tools (17 total) ==========

    # Checkov CI/CD: GitHub Actions workflow scanning
    # NOTE: checkov creates a DIRECTORY with --output-file, not a flat file
    # We must use --output-file-path (directory) and then move results_json.json
    if "checkov-cicd" in tools:
        checkov_cicd_out = out_dir / "checkov-cicd.json"
        checkov_cicd_temp_dir = out_dir / "checkov-cicd-temp"
        checkov_cicd_path = _find_tool("checkov", record_as="checkov-cicd")
        if checkov_cicd_path:
            checkov_cicd_flags = get_tool_flags("checkov-cicd")
            checkov_cicd_cmd = [
                checkov_cicd_path,
                "--framework",
                "github_actions",
                "--output",
                "json",
                "--output-file-path",
                str(checkov_cicd_temp_dir),
                *checkov_cicd_flags,
                "--directory",
                str(repo / ".github" / "workflows"),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="checkov-cicd",
                    command=checkov_cicd_cmd,
                    output_file=checkov_cicd_temp_dir / "results_json.json",
                    timeout=get_tool_timeout("checkov-cicd", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("checkov-cicd", checkov_cicd_out)
            statuses["checkov-cicd"] = True

    # Gosec: Go security analyzer
    if "gosec" in tools:
        gosec_out = out_dir / "gosec.json"
        gosec_path = _find_tool("gosec")
        if gosec_path:
            gosec_flags = get_tool_flags("gosec")
            gosec_cmd = [
                gosec_path,
                "-fmt=json",
                f"-out={gosec_out}",
                *gosec_flags,
                str(repo / "..."),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="gosec",
                    command=gosec_cmd,
                    output_file=gosec_out,
                    timeout=get_tool_timeout("gosec", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("gosec", gosec_out)
            statuses["gosec"] = True

    # cdxgen: SBOM and dependency analysis
    # Performance optimizations (v1.0.1):
    # - --no-install-deps: Don't run npm/pip install (major speedup, was causing 9+ min scans)
    # - --required-only: Skip optional/dev dependencies (reduces noise)
    # These can be overridden via per_tool_config flags if full analysis needed
    if "cdxgen" in tools:
        cdxgen_out = out_dir / "cdxgen.json"
        cdxgen_path = _find_tool("cdxgen")
        if cdxgen_path:
            cdxgen_flags = get_tool_flags("cdxgen")
            cdxgen_cmd = [
                cdxgen_path,
                "--no-install-deps",  # Don't install dependencies (major speedup)
                "--required-only",  # Only required deps, skip optional/dev
                "-o",
                str(cdxgen_out),
                *cdxgen_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="cdxgen",
                    command=cdxgen_cmd,
                    output_file=cdxgen_out,
                    timeout=get_tool_timeout("cdxgen", timeout),
                    retries=retries,
                    ok_return_codes=(0,),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("cdxgen", cdxgen_out)
            statuses["cdxgen"] = True

    # ScanCode: License and copyright scanner
    if "scancode" in tools:
        scancode_out = out_dir / "scancode.json"
        scancode_path = _find_tool("scancode")
        if scancode_path:
            scancode_flags = get_tool_flags("scancode")
            # ScanCode emits detection data only for the detectors it is asked
            # for. With none requested it walks the tree and writes structure
            # only -- `path`, `type`, `scan_errors` and nothing else -- so
            # `scancode_adapter`, which reads `license_detections` and
            # `copyrights`, was structurally incapable of returning a finding.
            # A `deep` scan spent up to twenty minutes producing a file that
            # could not contribute one, and graded the tool `success` (#835).
            #
            # Exactly the two the adapter reads. Measured against scancode
            # 32.5.0: `--license --copyright` and `--license --copyright
            # --package --info` produce the *same* 2 findings on the same
            # fixture, but the second writes 34 keys per entry against 11 --
            # 23 per entry that nothing consumes, on a tree that ran to 30,496
            # entries in the recorded juice-shop scan.
            scancode_cmd = [
                scancode_path,
                "--license",
                "--copyright",
                "--json",
                str(scancode_out),
                *scancode_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="scancode",
                    command=scancode_cmd,
                    output_file=scancode_out,
                    timeout=get_tool_timeout("scancode", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("scancode", scancode_out)
            statuses["scancode"] = True

    # Kubescape: Kubernetes security scanner
    if "kubescape" in tools:
        kubescape_out = out_dir / "kubescape.json"
        kubescape_path = _find_tool("kubescape")
        if kubescape_path:
            kubescape_flags = get_tool_flags("kubescape")
            kubescape_cmd = [
                kubescape_path,
                "scan",
                str(repo),
                "--format",
                "json",
                "--output",
                str(kubescape_out),
                *kubescape_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="kubescape",
                    command=kubescape_cmd,
                    output_file=kubescape_out,
                    timeout=get_tool_timeout("kubescape", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("kubescape", kubescape_out)
            statuses["kubescape"] = True

    # Prowler: Multi-cloud CSPM (AWS/Azure/GCP/K8s)
    # Note: Prowler scans cloud infrastructure, not code repositories
    # For repository scanning, we only run if cloud config files are detected
    if "prowler" in tools:
        prowler_out = out_dir / "prowler.json"
        # Check for cloud config files (terraform, cloudformation, etc.)
        cloud_files = (
            list(repo.glob("**/*.tf"))
            + list(repo.glob("**/*.tfvars"))
            + list(repo.glob("**/cloudformation.yaml"))
            + list(repo.glob("**/cloudformation.json"))
        )
        prowler_path = _find_tool("prowler")
        if cloud_files and prowler_path:
            prowler_flags = get_tool_flags("prowler")
            # `prowler iac` scans Infrastructure-as-Code from a local path with
            # no cloud credentials, which is what this branch wants - it is
            # gated on .tf/cloudformation files being present.
            #
            # What was here before could not run at all. prowler's CLI requires
            # a provider subcommand ({aws,azure,gcp,kubernetes,iac,...}); with
            # none, argparse printed usage and exited **2**, which is where the
            # reported "Return code 2 not in (0, 1, 3)" came from. Widening the
            # accepted set to include 2 would have been the wrong fix: 2 is
            # argparse's usage error, so accepting it means accepting "I passed
            # nonsense arguments" as a successful scan.
            #
            # `--output-formats json` was also invalid - prowler 5.x offers
            # {csv,json-asff,json-ocsf,html,sarif} and no plain `json`.
            prowler_cmd = [
                prowler_path,
                "iac",
                "--scan-path",
                str(repo),
                "--output-formats",
                "json-ocsf",
                "--output-directory",
                str(out_dir),
                "--output-filename",
                "prowler",
                # prowler renders a summary table to stdout that can raise
                # UnicodeEncodeError on a non-UTF-8 console. Nothing reads it.
                "--no-banner",
                *prowler_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="prowler",
                    command=prowler_cmd,
                    # The file prowler ACTUALLY writes, not the one the report
                    # phase wants. `--output-filename prowler` plus
                    # `--output-formats json-ocsf` yields `prowler.ocsf.json`,
                    # and ToolRunner checks this path the instant the process
                    # exits - before the rename below. Declaring `prowler.json`
                    # made it report `no_output` for a scan that had just
                    # written 372 KB, and the reconciler then saw the renamed
                    # artifact too and called prowler CONTRADICTORY.
                    output_file=out_dir / "prowler.ocsf.json",
                    timeout=get_tool_timeout("prowler", timeout),
                    retries=retries,
                    # 0=clean, 1=findings, 3=no credentials. NOT 2: that is
                    # argparse rejecting the command line.
                    ok_return_codes=(0, 1, 3),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools or not cloud_files:
            _write_stub("prowler", prowler_out)
            statuses["prowler"] = True

    # YARA: Malware detection
    if "yara" in tools:
        yara_out = out_dir / "yara.json"
        yara_path = _find_tool("yara")
        if yara_path:
            yara_flags = get_tool_flags("yara")
            # yara is libyara bindings, not a CLI, so `yara_path` is this
            # interpreter and scripts/core/yara_runner.py supplies the command
            # line. See that module for why the native CLI is not an option:
            # VirusTotal/yara publishes prebuilt binaries for Windows only, and
            # stopped even those at v4.5.6.
            #
            # What was here before could never have run. It built the native C
            # command line (`yara -r -w -s <rules> <repo>`) against a library
            # that has no executable; it pointed at /usr/share/yara/rules, which
            # is absent on Windows and on stock Ubuntu alike; and the adapter it
            # fed parses JSON, which yara's CLI has never emitted - the string
            # "json" does not appear anywhere in cli/yara.c.
            rules_path = per_tool_config.get("yara", {}).get(
                "rules_path", str(get_yara_rules_dir())
            )
            yara_cmd = [
                yara_path,
                "-m",
                "scripts.core.yara_runner",
                "--rules",
                str(rules_path),
                "--target",
                str(repo),
                "--output",
                str(yara_out),
                *yara_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="yara",
                    command=yara_cmd,
                    output_file=yara_out,
                    timeout=get_tool_timeout("yara", timeout),
                    retries=retries,
                    # 0 = clean, 1 = matches. The runner reserves 2 for "did NOT
                    # scan", which must stay a failure rather than an empty result.
                    ok_return_codes=(0, 1),
                    # The runner writes --output itself. Capturing stdout would
                    # overwrite that file with the runner's (empty) stdout.
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("yara", yara_out)
            statuses["yara"] = True

    # Grype: Vulnerability scanner for containers and filesystems
    if "grype" in tools:
        grype_out = out_dir / "grype.json"
        grype_path = _find_tool("grype")
        if grype_path:
            grype_flags = get_tool_flags("grype")
            grype_cmd = [
                grype_path,
                f"dir:{repo}",
                "-o",
                "json",
                *grype_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="grype",
                    command=grype_cmd,
                    output_file=grype_out,
                    timeout=get_tool_timeout("grype", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("grype", grype_out)
            statuses["grype"] = True

    # MobSF: Mobile Security Framework (Android/iOS)
    # Note: Only runs if APK/IPA files are detected
    if "mobsf" in tools:
        mobsf_out = out_dir / "mobsf.json"
        # Check for mobile app files
        mobile_files = list(repo.glob("**/*.apk")) + list(repo.glob("**/*.ipa"))
        mobsf_path = _find_tool("mobsf")
        if mobile_files and mobsf_path:
            mobsf_flags = get_tool_flags("mobsf")
            mobile_file = mobile_files[0]  # Scan first found mobile app
            mobsf_cmd = [
                mobsf_path,
                "-f",
                str(mobile_file),
                "-o",
                str(mobsf_out),
                *mobsf_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="mobsf",
                    command=mobsf_cmd,
                    output_file=mobsf_out,
                    timeout=get_tool_timeout("mobsf", timeout),
                    retries=retries,
                    ok_return_codes=(0,),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools or not mobile_files:
            _write_stub("mobsf", mobsf_out)
            statuses["mobsf"] = True

    # Lynis: System hardening and security auditing
    # Note: Lynis scans the local system, not code repositories
    # For repository scanning, we write a stub
    if "lynis" in tools:
        lynis_out = out_dir / "lynis.json"
        if allow_missing_tools:
            _write_stub("lynis", lynis_out)
            statuses["lynis"] = True

    # Trivy RBAC: Kubernetes RBAC security assessment
    # Note: Requires K8s manifests in repository
    if "trivy-rbac" in tools:
        trivy_rbac_out = out_dir / "trivy-rbac.json"
        # Check for K8s manifests
        k8s_manifests = (
            list(repo.glob("**/*deployment*.yaml"))
            + list(repo.glob("**/*service*.yaml"))
            + list(repo.glob("**/k8s/**/*.yaml"))
        )
        trivy_rbac_path = _find_tool("trivy", record_as="trivy-rbac")
        if k8s_manifests and trivy_rbac_path:
            trivy_rbac_flags = get_tool_flags("trivy-rbac")
            trivy_rbac_cmd = [
                trivy_rbac_path,
                "config",
                "--format",
                "json",
                "--output",
                str(trivy_rbac_out),
                "--scanners",
                "config",
                *trivy_rbac_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trivy-rbac",
                    command=trivy_rbac_cmd,
                    output_file=trivy_rbac_out,
                    timeout=get_tool_timeout("trivy-rbac", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools or not k8s_manifests:
            _write_stub("trivy-rbac", trivy_rbac_out)
            statuses["trivy-rbac"] = True

    # Semgrep Secrets: Hardcoded credentials detection
    if "semgrep-secrets" in tools:
        semgrep_secrets_out = out_dir / "semgrep-secrets.json"
        semgrep_secrets_path = _find_tool("semgrep", record_as="semgrep-secrets")
        if semgrep_secrets_path:
            semgrep_secrets_flags = get_tool_flags("semgrep-secrets")
            semgrep_secrets_cmd = [
                semgrep_secrets_path,
                "--config",
                "p/secrets",
                "--json",
                "--output",
                str(semgrep_secrets_out),
                *semgrep_secrets_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="semgrep-secrets",
                    command=semgrep_secrets_cmd,
                    output_file=semgrep_secrets_out,
                    timeout=get_tool_timeout("semgrep-secrets", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 2),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("semgrep-secrets", semgrep_secrets_out)
            statuses["semgrep-secrets"] = True

    # Horusec: Multi-language SAST scanner (18+ languages)
    # Uses --disable-docker (-D) flag to run native engines without Docker dependency
    # This allows horusec to work on systems where Docker is unavailable or not running
    if "horusec" in tools:
        horusec_out = out_dir / "horusec.json"
        horusec_path = _find_tool("horusec")
        if horusec_path:
            horusec_flags = get_tool_flags("horusec")
            horusec_cmd = [
                horusec_path,
                "start",
                "-p",
                str(repo),
                "-o",
                "json",
                "-O",
                str(horusec_out),
                "-D",  # Disable Docker - run native engines only
                *horusec_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="horusec",
                    command=horusec_cmd,
                    output_file=horusec_out,
                    timeout=get_tool_timeout("horusec", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("horusec", horusec_out)
            statuses["horusec"] = True

    # Dependency-Check: OWASP SCA for known vulnerabilities
    if "dependency-check" in tools:
        dependency_check_out = out_dir / "dependency-check.json"
        # find_tool checks both PATH and ~/.jmo/bin/dependency-check/bin/dependency-check.sh
        dc_path = _find_tool("dependency-check")
        if dc_path:
            dependency_check_flags = get_tool_flags("dependency-check")
            dependency_check_cmd = [
                dc_path,  # Use full path from find_tool
                "--project",
                name,
                "--scan",
                str(repo),
                "--format",
                "JSON",
                "--out",
                str(dependency_check_out),
                *dependency_check_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="dependency-check",
                    command=dependency_check_cmd,
                    output_file=dependency_check_out,
                    timeout=get_tool_timeout("dependency-check", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("dependency-check", dependency_check_out)
            statuses["dependency-check"] = True

    # ========== End of v1.0.0 New Tools ==========

    # A requested tool that never ran must say so. Silence here is the same
    # failure class as #700 (an accepted return code with no output written):
    # the scan looks complete, exits 0, and the missing tool's findings are
    # simply absent with nothing in the output to indicate it.
    #
    # Only tools that were *dropped*. Under --allow-missing-tools the `elif`
    # branch already wrote a stub and recorded the tool satisfied; that is a
    # deliberate, user-requested empty result, not a silent omission, so it must
    # not be overwritten here. Presence in `statuses` is what distinguishes the
    # two - a dropped tool has no entry at all, which is the whole problem.
    for missing in sorted(set(unresolved)):
        if missing in statuses:
            continue
        statuses[missing] = False
        # Name the dependency when the tool itself is not what was missing.
        # `zap` needs `zap-baseline.py` and `docker`; reporting the helper's
        # name alone sent the reader looking for a tool that is in no profile,
        # while the tool that actually lost its findings went unnamed.
        dep = missing_dependency.get(missing)
        what = f"its dependency `{dep}`" if dep else "its executable"
        logger.error(
            "%s: requested but %s could not be found - it did "
            "NOT run and its findings are MISSING from this scan. "
            "Run `jmo tools check` to confirm installation, or pass "
            "--allow-missing-tools to record an explicit empty result.",
            missing,
            what,
        )

    # Requested but never even attempted: this scanner has no code path for
    # them. nuclei scans URLs only and opa is evaluated in the report phase, so
    # both are correct to skip on a repository - but the profile still counts
    # them, which is why the progress bar reads [N/9] while fewer can run.
    # Kept distinct from `unresolved` so a genuinely missing binary is not lost
    # among tools that were never going to run.
    not_implemented = set(tools) - considered
    if not_implemented:
        logger.warning(
            "Requested but not applicable to repository targets (no repository "
            "implementation): %s",
            ", ".join(sorted(not_implemented)),
        )

    # Implemented and installed, but this repository had nothing for them to
    # look at - shellcheck on a repo with no shell scripts, hadolint with no
    # Dockerfiles. Benign, and reported at debug so it is available when a user
    # asks "why is there no shellcheck output?" without adding noise to a normal
    # run. Distinct from the two cases above: nothing is wrong here.
    idle = considered - set(unresolved) - {td.name for td in tool_defs} - set(statuses)
    if idle:
        logger.debug(
            "No matching files in %s for: %s",
            repo.name,
            ", ".join(sorted(idle)),
        )

    # Execute all tools with ToolRunner
    # Note: Tool progress is reported via progress_callback, not direct stderr prints
    # This prevents overlapping output when Rich progress display is active
    runner = ToolRunner(
        tools=tool_defs,
        progress_callback=progress_callback,  # type: ignore[arg-type]
    )
    tools_started = time.perf_counter()
    results = runner.run_all_parallel()

    # ToolRunner already timed and classified every invocation. Record that
    # before the loop below reduces the results to booleans, which is where it
    # used to be lost (#722).
    write_scan_timings(
        out_dir,
        results,
        target=name,
        target_type="repo",
        wall_seconds=time.perf_counter() - tools_started,
    )

    # Process results
    attempts_map: dict[str, int] = {}
    noseyparker_phases = {"init": False, "scan": False, "report": False}

    for result in results:
        # Handle multi-phase noseyparker execution
        if result.tool.startswith("noseyparker-"):
            phase = result.tool.split("-")[1]  # Extract "init", "scan", or "report"
            if result.status == "success":
                noseyparker_phases[phase] = True
                if phase == "report" and result.output_file and result.capture_stdout:
                    result.output_file.write_text(result.stdout or "", encoding="utf-8")
            else:
                noseyparker_phases[phase] = False
            continue  # Don't set individual phase status in statuses dict

        # prowler names its own artifact. `--output-filename prowler` with
        # `--output-formats json-ocsf` produces `prowler.ocsf.json`, so the
        # declared output_file (`prowler.json`) would never appear and the tool
        # would be recorded `no_output` after a scan that genuinely worked.
        if result.tool == "prowler":
            ocsf_out = out_dir / "prowler.ocsf.json"
            prowler_json = out_dir / "prowler.json"
            if ocsf_out.exists() and not prowler_json.exists():
                ocsf_out.replace(prowler_json)

        # Handle checkov-cicd special case: move results from temp directory
        if result.tool == "checkov-cicd" and result.status == "success":
            # checkov creates: checkov-cicd-temp/results_json.json
            # We need: checkov-cicd.json (flat file)
            import shutil

            checkov_cicd_out = out_dir / "checkov-cicd.json"
            checkov_cicd_temp_dir = out_dir / "checkov-cicd-temp"
            checkov_cicd_temp_file = checkov_cicd_temp_dir / "results_json.json"
            if checkov_cicd_temp_file.exists():
                shutil.move(str(checkov_cicd_temp_file), str(checkov_cicd_out))
                # Clean up temp directory
                shutil.rmtree(checkov_cicd_temp_dir, ignore_errors=True)

        if result.status == "success":
            # Write stdout to file ONLY if we captured it (capture_stdout=True)
            # Tools with capture_stdout=False write their own files (semgrep, trivy, bandit)
            if result.output_file and result.capture_stdout:
                result.output_file.write_text(result.stdout or "", encoding="utf-8")
            statuses[result.tool] = True
            if result.attempts > 1:
                attempts_map[result.tool] = result.attempts
        elif result.status == "error" and "Tool not found" in result.error_message:
            # Reaching here means the tool RESOLVED in pre-flight - it was given
            # a ToolDefinition and handed to ToolRunner - and then could not be
            # executed. That is always a defect: a resolver returning something
            # that is not a path, or a binary that vanished mid-scan. A tool the
            # user genuinely has not installed never gets this far; it is
            # dropped or stubbed in pre-flight.
            #
            # So --allow-missing-tools must NOT absorb it. That flag means
            # "record an explicit empty result for tools I know I lack", which
            # is not consent to swallow a resolver bug. It used to write a stub
            # and set True here: find_tool("yara") returned the pseudo-path
            # "python:yara", which is truthy and so passed pre-flight, then
            # raised FileNotFoundError at exec. Measured on a machine with HOME
            # and PATH stripped - where yara could not possibly have run - the
            # scan wrote yara.json and reported a clean malware scan.
            #
            # No stub, either: an empty stub is indistinguishable from a genuine
            # empty result once the report phase reads it, which is the precise
            # lie being removed.
            statuses[result.tool] = False
            report_tool_failure(result, "its executable was not found at run time")
        elif result.timed_out:
            # Tool timed out - write stub so report phase has consistent files
            # and mark as failed (timeout is a failure state)
            #
            # `result.timed_out`, not `"Timeout" in result.error_message` (#727).
            # That match made a human-readable message load-bearing: rewording
            # "Timeout after 600s" would have silently routed every timeout to
            # the generic branch below, dropping the stub and the "it timed out"
            # log line, with nothing going red.
            #
            # The stub must not be the only signal: once the report phase reads
            # it, an empty stub is indistinguishable from a tool that genuinely
            # found nothing. The timeout has to be stated here or it is lost.
            tool_out = out_dir / f"{result.tool}.json"
            if not tool_out.exists():
                _write_stub(result.tool, tool_out)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            report_tool_failure(result, "it timed out")
        else:
            # Other errors (non-zero exit, etc.)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            # `no_output` - an accepted return code with nothing written - is
            # also announced by the progress tracker, but that is a UI surface:
            # bare text rather than the log stream, and overwritten in place on
            # a TTY. It is not a durable record, so this must still log. The
            # #700 class of bug is precisely a tool that returns 0 and produces
            # nothing; that must survive into the log.
            report_tool_failure(
                result,
                (
                    "it exited with an accepted code but wrote no output"
                    if result.status == "no_output"
                    else "it failed"
                ),
            )

    # Aggregate noseyparker multi-phase status
    if any(noseyparker_phases.values()):
        # If any phase succeeded, check if all required phases succeeded
        if (
            noseyparker_phases["init"]
            and noseyparker_phases["scan"]
            and noseyparker_phases["report"]
        ):
            statuses["noseyparker"] = True
        elif allow_missing_tools:
            # Partial success - write stub
            noseyparker_out = out_dir / "noseyparker.json"
            _write_stub("noseyparker", noseyparker_out)
            statuses["noseyparker"] = True
        else:
            statuses["noseyparker"] = False

    # Include attempts metadata if any retries occurred
    if attempts_map:
        statuses["__attempts__"] = attempts_map  # type: ignore[assignment]  # Store retry metadata alongside bool statuses

    return name, statuses
