#!/usr/bin/env python3
"""Compressed size of a published image, per platform, as its registry reports it.

`docker manifest inspect` on a multi-arch tag returns the image INDEX, and its
`manifests[].size` is the byte length of each platform's manifest document, a
few KB, not of the image. release.yml's size benchmark printed exactly that for
v1.1.1: `deep | 7.8KiB | 7.8KiB` (#1482). An image's compressed size is the sum
of `layers[].size` in its platform's own manifest, which this resolves from the
index by digest, skipping the index's attestation entries (`unknown/unknown`).

One implementation for two callers: release.yml's docker-size-benchmark job
prints its table, and `registry_compressed_mb` in
tests/e2e/test_docker_workflows.py reads the linux/amd64 number to judge
IMAGE_SIZE_RANGE, so the two cannot disagree.

Standard library only: the release job runs it with the runner's python3 and
no project venv.

    python3 scripts/dev/image_size.py IMAGE [ARCH ...]   (default: amd64 arm64)

prints a markdown table, one row per platform, and exits 1 with the reason when
any size cannot be read.
"""

from __future__ import annotations

import json
import subprocess
import sys

INSPECT_TIMEOUT_S = 60
MIB = 1024 * 1024


class ImageSizeError(Exception):
    """A size that cannot be read. Never reported as a number."""


def _inspect(ref: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", ref],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=INSPECT_TIMEOUT_S,
        )
    except FileNotFoundError as exc:
        raise ImageSizeError("docker is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ImageSizeError(
            f"docker manifest inspect {ref} ran past {INSPECT_TIMEOUT_S}s"
        ) from exc
    if result.returncode != 0:
        raise ImageSizeError(
            f"docker manifest inspect {ref} failed (rc={result.returncode}): "
            f"{result.stderr.strip()[:400]}"
        )
    doc: dict = json.loads(result.stdout)
    return doc


def compressed_bytes(
    image: str, arch: str = "amd64", *, need_index: bool = False
) -> int:
    """Sum of the layer sizes of ``image``'s linux/``arch`` manifest.

    A single-platform manifest carries no platform of its own, so it is read as
    it is, unless ``need_index``: then only an index will do, since one
    manifest's layers printed under two platform labels would be a wrong table.
    """
    repo = image.rsplit(":", 1)[0]
    doc = _inspect(image)
    layers = doc.get("layers")
    if layers is None:
        digests = [
            m["digest"]
            for m in doc.get("manifests", [])
            if m.get("platform", {}).get("architecture") == arch
            and m.get("platform", {}).get("os") == "linux"
        ]
        if not digests:
            raise ImageSizeError(f"{image}: the index has no linux/{arch} entry")
        layers = _inspect(f"{repo}@{digests[0]}").get("layers", [])
    elif need_index:
        raise ImageSizeError(
            f"{image} is a single-platform manifest, not an index: "
            f"its layers cannot be attributed to linux/{arch}"
        )

    total = sum(int(layer["size"]) for layer in layers)
    if total <= 0:
        raise ImageSizeError(
            f"{image}: linux/{arch} reported {len(layers)} layer(s) "
            f"totalling {total} bytes, which cannot be right"
        )
    return total


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    image, arches = argv[0], argv[1:] or ["amd64", "arm64"]
    try:
        sizes = {
            arch: compressed_bytes(image, arch, need_index=True) for arch in arches
        }
    except ImageSizeError as exc:
        # stderr: release.yml sends stdout, the table, into a file.
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print("| Image | Platform | Compressed size |")
    print("|-------|----------|-----------------|")
    for arch, size in sizes.items():
        print(f"| {image} | linux/{arch} | {size / MIB:.1f} MiB |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
