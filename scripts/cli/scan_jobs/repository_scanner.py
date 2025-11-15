"""
Repository Scanner

Scans local Git repositories using multiple security tools.

Fully Implemented Tools (28 total for v1.0.0):

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

v1.0.0 New Tools (17):
12. Checkov CI/CD: GitHub Actions workflow security
13. Gosec: Go security analyzer
14. OSV-Scanner: Open source vulnerability detection
15. cdxgen: SBOM and dependency analysis
16. ScanCode: License and copyright scanner
17. Kubescape: Kubernetes security scanner
18. Bearer: Data security and privacy scanner
19. Prowler: Multi-cloud CSPM (AWS/Azure/GCP/K8s)
20. YARA: Malware detection
21. Grype: Vulnerability scanner for containers/filesystems
22. MobSF: Mobile Security Framework (Android/iOS)
23. Lynis: System hardening and security auditing
24. Trivy RBAC: Kubernetes RBAC security assessment
25. Semgrep Secrets: Hardcoded credentials detection
26. Horusec: Multi-language SAST (18+ languages)
27. Dependency-Check: OWASP SCA for known vulnerabilities
28. Akto: API Security testing (URL scanner only)

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

from pathlib import Path
from collections.abc import Callable

from ...core.tool_runner import ToolRunner, ToolDefinition
from ..scan_utils import tool_exists, write_stub


def scan_repository(
    repo: Path,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int,
    per_tool_config: dict,
    allow_missing_tools: bool,
    tool_exists_func: Callable[[str], bool] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
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

    Returns:
        Tuple of (repo_name, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    statuses: dict[str, bool] = {}
    tool_defs = []

    # Use provided functions or defaults
    _tool_exists = tool_exists_func or tool_exists
    _write_stub = write_stub_func or write_stub

    name = repo.name
    out_dir = results_dir / name
    out_dir.mkdir(parents=True, exist_ok=True)

    def get_tool_timeout(tool: str, default: int) -> int:
        """Get timeout override for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            override = tool_cfg.get("timeout")
            if isinstance(override, int) and override > 0:
                return override
        return default

    def get_tool_flags(tool: str) -> list[str]:
        """Get additional flags for specific tool."""
        tool_cfg = per_tool_config.get(tool, {})
        if isinstance(tool_cfg, dict):
            flags = tool_cfg.get("flags", [])
            if isinstance(flags, list):
                return [str(f) for f in flags]
        return []

    # TruffleHog: Verified secrets scanning
    if "trufflehog" in tools:
        trufflehog_out = out_dir / "trufflehog.json"
        if _tool_exists("trufflehog"):
            trufflehog_flags = get_tool_flags("trufflehog")
            trufflehog_cmd = [
                "trufflehog",
                "git",
                f"file://{repo}",
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
        if _tool_exists("semgrep"):
            semgrep_flags = get_tool_flags("semgrep")
            semgrep_cmd = [
                "semgrep",
                "--config=auto",
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
        if _tool_exists("trivy"):
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                "trivy",
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
        if _tool_exists("syft"):
            syft_flags = get_tool_flags("syft")
            syft_cmd = [
                "syft",
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
        if _tool_exists("checkov"):
            checkov_flags = get_tool_flags("checkov")
            checkov_cmd = [
                "checkov",
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
        if _tool_exists("hadolint"):
            hadolint_flags = get_tool_flags("hadolint")

            # Find Dockerfiles in repository
            dockerfiles = list(repo.glob("**/Dockerfile*"))
            if dockerfiles:
                # Hadolint scans one file at a time; use first Dockerfile found
                dockerfile = dockerfiles[0]
                hadolint_cmd = [
                    "hadolint",
                    "-f",
                    "json",
                    *hadolint_flags,
                    str(dockerfile),
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

    # Bandit: Python security analysis
    if "bandit" in tools:
        bandit_out = out_dir / "bandit.json"
        if _tool_exists("bandit"):
            bandit_flags = get_tool_flags("bandit")
            bandit_cmd = [
                "bandit",
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
        if _tool_exists("noseyparker"):
            # Nosey Parker requires a datastore directory
            datastore_dir = out_dir / ".noseyparker_datastore"
            datastore_dir.mkdir(parents=True, exist_ok=True)

            # Phase 1: Initialize datastore (idempotent)
            init_cmd = [
                "noseyparker",
                "datastore",
                "init",
                "--datastore",
                str(datastore_dir),
            ]
            # Phase 2: Scan repository
            scan_cmd = [
                "noseyparker",
                "scan",
                "--datastore",
                str(datastore_dir),
                str(repo),
                *noseyparker_flags,
            ]
            # Phase 3: Generate JSON report
            report_cmd = [
                "noseyparker",
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
        elif (
            _tool_exists("docker")
            and Path(__file__)
            .parent.parent.parent.joinpath("core/run_noseyparker_docker.sh")
            .exists()
        ):
            docker_script = (
                Path(__file__).parent.parent.parent / "core/run_noseyparker_docker.sh"
            )
            docker_cmd = [
                "bash",
                str(docker_script),
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
        if _tool_exists("zap-baseline.py") or _tool_exists("docker"):
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
                if _tool_exists("zap-baseline.py"):
                    zap_cmd = [
                        "zap-baseline.py",
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
                elif _tool_exists("docker"):
                    # Fallback to Docker-based ZAP
                    zap_cmd = [
                        "docker",
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
        if _tool_exists("falco"):
            falco_flags = get_tool_flags("falco")
            # Look for Falco rule files in repository
            falco_rules = list(repo.glob("**/*falco*.yaml")) + list(
                repo.glob("**/*falco*.yml")
            )
            if falco_rules:
                # Validate Falco rules using falco --validate
                rules_file = falco_rules[0]
                falco_cmd = [
                    "falco",
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
        if _tool_exists("afl-fuzz") or _tool_exists("afl-analyze"):
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

            if binaries and _tool_exists("afl-analyze"):
                # Run afl-analyze on the first binary found
                binary = binaries[0]
                # Create minimal input corpus
                corpus_dir = out_dir / ".afl_corpus"
                corpus_dir.mkdir(parents=True, exist_ok=True)
                (corpus_dir / "test1").write_bytes(b"test")

                # Run AFL++ dry run (no actual fuzzing, just validation)
                afl_cmd = [
                    "afl-fuzz",
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
        if _tool_exists("checkov"):
            checkov_cicd_flags = get_tool_flags("checkov-cicd")
            checkov_cicd_cmd = [
                "checkov",
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
        if _tool_exists("gosec"):
            gosec_flags = get_tool_flags("gosec")
            gosec_cmd = [
                "gosec",
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

    # OSV-Scanner: Vulnerability scanner for open source
    if "osv-scanner" in tools:
        osv_out = out_dir / "osv.json"
        if _tool_exists("osv-scanner"):
            osv_flags = get_tool_flags("osv-scanner")
            osv_cmd = [
                "osv-scanner",
                "--format",
                "json",
                "--output",
                str(osv_out),
                *osv_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="osv-scanner",
                    command=osv_cmd,
                    output_file=osv_out,
                    timeout=get_tool_timeout("osv-scanner", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("osv-scanner", osv_out)
            statuses["osv-scanner"] = True

    # cdxgen: SBOM and dependency analysis
    if "cdxgen" in tools:
        cdxgen_out = out_dir / "cdxgen.json"
        if _tool_exists("cdxgen"):
            cdxgen_flags = get_tool_flags("cdxgen")
            cdxgen_cmd = [
                "cdxgen",
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
        if _tool_exists("scancode"):
            scancode_flags = get_tool_flags("scancode")
            scancode_cmd = [
                "scancode",
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
        if _tool_exists("kubescape"):
            kubescape_flags = get_tool_flags("kubescape")
            kubescape_cmd = [
                "kubescape",
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

    # Bearer: Data security and privacy scanner
    if "bearer" in tools:
        bearer_out = out_dir / "bearer.json"
        if _tool_exists("bearer"):
            bearer_flags = get_tool_flags("bearer")
            bearer_cmd = [
                "bearer",
                "scan",
                str(repo),
                "--format",
                "json",
                "--output",
                str(bearer_out),
                *bearer_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="bearer",
                    command=bearer_cmd,
                    output_file=bearer_out,
                    timeout=get_tool_timeout("bearer", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("bearer", bearer_out)
            statuses["bearer"] = True

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
        if cloud_files and _tool_exists("prowler"):
            prowler_flags = get_tool_flags("prowler")
            # Run Prowler in configuration scanning mode
            prowler_cmd = [
                "prowler",
                "--output-formats",
                "json",
                "--output-directory",
                str(out_dir),
                "--output-filename",
                "prowler",
                *prowler_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="prowler",
                    command=prowler_cmd,
                    output_file=prowler_out,
                    timeout=get_tool_timeout("prowler", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 3),  # 0=clean, 1=findings, 3=no credentials
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools or not cloud_files:
            _write_stub("prowler", prowler_out)
            statuses["prowler"] = True

    # YARA: Malware detection
    if "yara" in tools:
        yara_out = out_dir / "yara.json"
        if _tool_exists("yara"):
            yara_flags = get_tool_flags("yara")
            # Use built-in rules or user-provided rules
            rules_path = per_tool_config.get("yara", {}).get(
                "rules_path", "/usr/share/yara/rules"
            )
            yara_cmd = [
                "yara",
                "-r",  # Recursive
                "-w",  # Disable warnings
                "-s",  # Print matched strings
                *yara_flags,
                str(rules_path),
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="yara",
                    command=yara_cmd,
                    output_file=yara_out,
                    timeout=get_tool_timeout("yara", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("yara", yara_out)
            statuses["yara"] = True

    # Grype: Vulnerability scanner for containers and filesystems
    if "grype" in tools:
        grype_out = out_dir / "grype.json"
        if _tool_exists("grype"):
            grype_flags = get_tool_flags("grype")
            grype_cmd = [
                "grype",
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
        if mobile_files and _tool_exists("mobsf"):
            mobsf_flags = get_tool_flags("mobsf")
            mobile_file = mobile_files[0]  # Scan first found mobile app
            mobsf_cmd = [
                "mobsf",
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
        if k8s_manifests and _tool_exists("trivy"):
            trivy_rbac_flags = get_tool_flags("trivy-rbac")
            trivy_rbac_cmd = [
                "trivy",
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
        if _tool_exists("semgrep"):
            semgrep_secrets_flags = get_tool_flags("semgrep-secrets")
            semgrep_secrets_cmd = [
                "semgrep",
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
    if "horusec" in tools:
        horusec_out = out_dir / "horusec.json"
        if _tool_exists("horusec"):
            horusec_flags = get_tool_flags("horusec")
            horusec_cmd = [
                "horusec",
                "start",
                "-p",
                str(repo),
                "-o",
                "json",
                "-O",
                str(horusec_out),
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
        if _tool_exists("dependency-check"):
            dependency_check_flags = get_tool_flags("dependency-check")
            dependency_check_cmd = [
                "dependency-check",
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

    # Execute all tools with ToolRunner
    if tool_defs:
        tool_names = [t.name for t in tool_defs]
        import sys

        print(
            f"INFO: Running {len(tool_defs)} tools on {name}: {', '.join(tool_names)}",
            file=sys.stderr,
        )

    runner = ToolRunner(
        tools=tool_defs,
    )
    results = runner.run_all_parallel()

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
            # Tool doesn't exist - write stub if allow_missing_tools
            if allow_missing_tools:
                tool_out = out_dir / f"{result.tool}.json"
                _write_stub(result.tool, tool_out)
                statuses[result.tool] = True
            else:
                statuses[result.tool] = False
        else:
            # Other errors (timeout, non-zero exit, etc.)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts

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
        statuses["__attempts__"] = attempts_map  # type: ignore

    return name, statuses
