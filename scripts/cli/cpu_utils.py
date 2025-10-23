#!/usr/bin/env python3
"""
CPU utility functions for JMo Security.

Provides shared CPU detection and thread optimization logic used by both
the main CLI (jmo.py) and the interactive wizard (wizard.py).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def get_cpu_count() -> int:
    """
    Get CPU count with fallback.

    Returns:
        int: Number of CPU cores, or 4 if detection fails
    """
    try:
        return os.cpu_count() or 4
    except (OSError, RuntimeError) as e:
        # CPU count detection can fail on some systems or be mocked in tests
        logger.debug(f"Failed to detect CPU count: {e}")
        return 4


def auto_detect_threads(log_fn=None) -> int:
    """
    Auto-detect optimal thread count based on CPU cores.

    Strategy:
    - Use 75% of available CPU cores (leave headroom for system)
    - Minimum: 2 threads (for small systems)
    - Maximum: 16 threads (diminishing returns beyond this)

    Args:
        log_fn: Optional logging function for verbose output

    Returns:
        int: Optimal thread count
    """
    cpu_count = get_cpu_count()

    # Use 75% of cores, leave 25% for system/other processes
    optimal = max(2, int(cpu_count * 0.75))

    # Cap at 16 threads (diminishing returns beyond this)
    optimal = min(optimal, 16)

    if log_fn:
        log_fn(
            "INFO",
            f"Auto-detected {cpu_count} CPU cores, using {optimal} threads (75% utilization)",
        )

    return optimal
