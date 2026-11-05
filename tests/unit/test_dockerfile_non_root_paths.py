"""The image's cache paths are the non-root user's (#1375).

The image runs as `jmo` (uid 1000), and trivy caches under that user's home,
/home/jmo/.cache/trivy. `VOLUME ["/root/.cache/trivy"]` was left from a root
image: nothing used it, and Docker made an anonymous volume for it on every
run. A named volume on a directory the image does not create comes up owned by
root, which jmo cannot write, so the image creates its cache directory owned
by jmo. Decided 2026-11-05 (D4).

A Dockerfile line is not a build: docker-smoke builds this one on the PR, and
the docker tests mount the documented paths. This guards the shape between.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"


def _instructions() -> list[str]:
    """Each instruction of the Dockerfile, its continuation lines joined."""
    text = DOCKERFILE.read_bytes().decode("utf-8")
    joined = re.sub(r"\\\n", " ", text)
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_no_volume_or_ownership_names_roots_home() -> None:
    volumes = [i for i in _instructions() if i.startswith("VOLUME")]
    assert not [v for v in volumes if "/root/" in v], volumes
    chowns = [i for i in _instructions() if "chown" in i]
    assert not [c for c in chowns if re.search(r"\s/root/\.cache\b", c)], chowns


def test_the_trivy_cache_exists_owned_by_the_image_user() -> None:
    (setup,) = [i for i in _instructions() if "useradd" in i]

    assert re.search(r"mkdir -p [^&]*/home/jmo/\.cache/trivy", setup), setup
    assert re.search(r"chown -R jmo:jmo [^&]*/home/jmo(\s|$)", setup), setup
