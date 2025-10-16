#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, TYPE_CHECKING, Any as AnyType

if TYPE_CHECKING:
    import yaml as YamlModule
else:
    try:
        import yaml as YamlModule  # type: ignore[assignment]
    except ImportError:
        YamlModule = None  # type: ignore[assignment]

yaml: Optional[AnyType] = YamlModule


@dataclass
class Config:
    tools: List[str] = field(
        default_factory=lambda: [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
        ]
    )
    outputs: List[str] = field(default_factory=lambda: ["json", "md", "yaml", "html"])
    fail_on: str = ""
    threads: Optional[int] = None
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    timeout: Optional[int] = None
    log_level: str = "INFO"
    # Advanced
    default_profile: Optional[str] = None
    profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    per_tool: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    retries: int = 0
    # Profiling thread recommendations (used when --profile flag set)
    profiling_min_threads: int = 2
    profiling_max_threads: int = 8
    profiling_default_threads: int = 4


def load_config(path: Optional[str]) -> Config:
    if not path:
        return Config()
    p = Path(path)
    if not p.exists():
        return Config()
    if yaml is None:
        return Config()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cfg = Config()
    if isinstance(data.get("tools"), list):
        cfg.tools = [str(x) for x in data["tools"]]
    if isinstance(data.get("outputs"), list):
        cfg.outputs = [str(x) for x in data["outputs"]]
    if isinstance(data.get("fail_on"), str):
        cfg.fail_on = data["fail_on"].upper()
    # threads: optional positive int; <=0 or missing -> None (auto)
    tval = data.get("threads")
    if isinstance(tval, int) and tval > 0:
        cfg.threads = tval
    # include/exclude
    if isinstance(data.get("include"), list):
        cfg.include = [str(x) for x in data["include"]]
    if isinstance(data.get("exclude"), list):
        cfg.exclude = [str(x) for x in data["exclude"]]
    # timeout
    tv = data.get("timeout")
    if isinstance(tv, int) and tv > 0:
        cfg.timeout = tv
    # log_level
    if isinstance(data.get("log_level"), str):
        lvl = str(data["log_level"]).upper()
        if lvl in ("DEBUG", "INFO", "WARN", "ERROR"):
            cfg.log_level = lvl
    # default_profile
    if isinstance(data.get("default_profile"), str):
        cfg.default_profile = str(data["default_profile"]).strip() or None
    # profiles (free-form dict)
    if isinstance(data.get("profiles"), dict):
        cfg.profiles = data["profiles"]
    # per_tool overrides
    if isinstance(data.get("per_tool"), dict):
        cfg.per_tool = data["per_tool"]
    # retries
    rv = data.get("retries")
    if isinstance(rv, int) and rv >= 0:
        cfg.retries = rv
    # profiling thread recommendations
    if "profiling" in data and isinstance(data["profiling"], dict):
        prof = data["profiling"]
        if isinstance(prof.get("min_threads"), int) and prof["min_threads"] > 0:
            cfg.profiling_min_threads = prof["min_threads"]
        if isinstance(prof.get("max_threads"), int) and prof["max_threads"] > 0:
            cfg.profiling_max_threads = prof["max_threads"]
        if isinstance(prof.get("default_threads"), int) and prof["default_threads"] > 0:
            cfg.profiling_default_threads = prof["default_threads"]
    return cfg
