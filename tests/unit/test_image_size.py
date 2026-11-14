"""An image's size is its platform manifest's layers, not the index entry (#1482).

release.yml's size benchmark read `manifests[].size` from the multi-arch index,
the byte length of each platform's manifest document, and printed
`deep | 7.8KiB` for v1.1.1. `scripts/dev/image_size.py` resolves each
platform's manifest by digest and sums its layers, and it is the one
measurement behind both the release table and `registry_compressed_mb` in
tests/e2e/test_docker_workflows.py. The index below has v1.1.1's shape on GHCR:
two platforms, each with an `unknown/unknown` attestation entry beside it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.dev import image_size

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

REPO = "ghcr.io/owner/jmo-security"
IMAGE = f"{REPO}:2.0.0"
AMD64 = "sha256:" + "a" * 64
ARM64 = "sha256:" + "b" * 64
AMD64_LAYERS = [838_860_800, 1_101_319_373, 4_096]
ARM64_LAYERS = [805_306_368, 1_048_576_000]


def _entry(digest: str, arch: str, os_: str = "linux", size: int = 7985) -> dict:
    return {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": size,
        "digest": digest,
        "platform": {"architecture": arch, "os": os_},
    }


INDEX = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
        _entry(AMD64, "amd64"),
        _entry("sha256:" + "c" * 64, "unknown", "unknown", 1114),
        _entry(ARM64, "arm64", size=7979),
        _entry("sha256:" + "d" * 64, "unknown", "unknown", 1114),
    ],
}


def _manifest(layers: list[int]) -> dict:
    return {"schemaVersion": 2, "layers": [{"size": s} for s in layers]}


REGISTRY = {
    IMAGE: INDEX,
    f"{REPO}@{AMD64}": _manifest(AMD64_LAYERS),
    f"{REPO}@{ARM64}": _manifest(ARM64_LAYERS),
}


@pytest.fixture
def registry(monkeypatch):
    """`_inspect` answering from a dict, as the registry would."""
    table = dict(REGISTRY)

    def inspect(ref: str) -> dict:
        if ref not in table:
            raise image_size.ImageSizeError(f"manifest unknown: {ref}")
        return table[ref]

    monkeypatch.setattr(image_size, "_inspect", inspect)
    return table


def test_the_size_is_the_platforms_layers_not_its_index_entry(registry) -> None:
    assert image_size.compressed_bytes(IMAGE, "amd64") == sum(AMD64_LAYERS)
    assert image_size.compressed_bytes(IMAGE, "arm64") == sum(ARM64_LAYERS)
    # What the old benchmark printed: the manifest document's own size.
    assert image_size.compressed_bytes(IMAGE, "amd64") != 7985


def test_an_attestation_entry_is_not_a_platform(registry) -> None:
    registry[IMAGE] = {**INDEX, "manifests": INDEX["manifests"][:2]}
    with pytest.raises(image_size.ImageSizeError, match="no linux/arm64 entry"):
        image_size.compressed_bytes(IMAGE, "arm64")


def test_a_manifest_with_no_layer_size_is_an_error_not_zero(registry) -> None:
    registry[f"{REPO}@{AMD64}"] = _manifest([])
    with pytest.raises(image_size.ImageSizeError, match="totalling 0 bytes"):
        image_size.compressed_bytes(IMAGE, "amd64")


def test_a_single_platform_manifest_is_read_as_it_is(registry) -> None:
    registry[IMAGE] = _manifest(AMD64_LAYERS)
    assert image_size.compressed_bytes(IMAGE, "amd64") == sum(AMD64_LAYERS)


def test_the_table_refuses_a_single_platform_manifest(registry, capsys) -> None:
    """One manifest's layers printed under two platform labels is a wrong
    table, so the CLI fails rather than print it."""
    registry[IMAGE] = _manifest(AMD64_LAYERS)
    assert image_size.main([IMAGE]) == 1
    assert "not an index" in capsys.readouterr().err


def test_the_table_prints_mib_per_platform(registry, capsys) -> None:
    assert image_size.main([IMAGE]) == 0
    out = capsys.readouterr().out
    assert f"| {IMAGE} | linux/amd64 | {sum(AMD64_LAYERS) / 2**20:.1f} MiB |" in out
    assert f"| {IMAGE} | linux/arm64 | {sum(ARM64_LAYERS) / 2**20:.1f} MiB |" in out


def test_a_missing_tag_fails_the_table(registry, capsys) -> None:
    assert image_size.main([f"{REPO}:9.9.9"]) == 1
    assert "::error::manifest unknown" in capsys.readouterr().err


# The release job and the e2e helper, run against one fake `docker` that
# answers `docker manifest inspect REF` from REGISTRY.
needs_posix = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="release.yml's step runs under bash on ubuntu-latest",
)


class FakeRegistry:
    """What the fake `docker` serves: edit `table`, then `write()`."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.table = dict(REGISTRY)
        self.write()

    def write(self) -> None:
        self.path.write_bytes(json.dumps(self.table).encode())


@pytest.fixture
def fake_docker(tmp_path, monkeypatch) -> FakeRegistry:
    registry = FakeRegistry(tmp_path / "registry.json")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_bytes(
        (
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "table = json.load(open(os.environ['FAKE_REGISTRY']))\n"
            "ref = sys.argv[-1]\n"
            "if sys.argv[1:3] != ['manifest', 'inspect'] or ref not in table:\n"
            "    sys.stderr.write(f'manifest unknown: {ref}\\n')\n"
            "    sys.exit(1)\n"
            "print(json.dumps(table[ref]))\n"
        ).encode()
    )
    docker.chmod(0o755)
    monkeypatch.setenv("FAKE_REGISTRY", str(registry.path))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return registry


def _release_step(tmp_path: Path) -> subprocess.CompletedProcess:
    job = yaml.safe_load(RELEASE.read_bytes())["jobs"]["docker-size-benchmark"]
    (step,) = [s for s in job["steps"] if s.get("name") == "Measure the image"]
    # The step runs scripts/dev/image_size.py from the checkout's root.
    work = tmp_path / "work"
    (work / "scripts" / "dev").mkdir(parents=True)
    shutil.copyfile(
        ROOT / "scripts" / "dev" / "image_size.py",
        work / "scripts" / "dev" / "image_size.py",
    )
    (work / "step.sh").write_bytes(step["run"].encode())
    return subprocess.run(
        # GitHub's default shell for a `run:` step with no `shell:`.
        ["bash", "-e", "step.sh"],
        cwd=work,
        env={
            **os.environ,
            "REF_NAME": "v2.0.0",
            "TAG_VALUE": "2.0.0",
            "REGISTRY": "ghcr.io",
            "IMAGE_NAME": "owner/jmo-security",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_the_release_job_needs_a_checkout_for_the_script() -> None:
    job = yaml.safe_load(RELEASE.read_bytes())["jobs"]["docker-size-benchmark"]
    uses = [s.get("uses", "") for s in job["steps"]]
    assert any(u.startswith("actions/checkout@") for u in uses), uses


@needs_posix
def test_the_release_step_prints_each_platforms_image_size(
    tmp_path, fake_docker
) -> None:
    done = _release_step(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"| linux/amd64 | {sum(AMD64_LAYERS) / 2**20:.1f} MiB |" in done.stdout
    assert f"| linux/arm64 | {sum(ARM64_LAYERS) / 2**20:.1f} MiB |" in done.stdout
    assert "KiB" not in done.stdout
    assert "155 MB" not in done.stdout


@needs_posix
def test_the_release_step_fails_when_a_size_cannot_be_read(
    tmp_path, fake_docker
) -> None:
    del fake_docker.table[f"{REPO}@{ARM64}"]
    fake_docker.write()
    done = _release_step(tmp_path)
    assert done.returncode != 0
    # In the job's log, not only in the table file the step writes.
    assert done.stderr.startswith("::error::"), done.stderr
    assert f"manifest unknown: {REPO}@{ARM64}" in done.stderr


@needs_posix
def test_the_e2e_range_check_reads_the_release_tables_number(
    tmp_path, fake_docker
) -> None:
    """The issue's acceptance: the release job's MiB agrees with
    `registry_compressed_mb` within rounding."""
    from tests.e2e.test_docker_workflows import registry_compressed_mb

    done = _release_step(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    mib = registry_compressed_mb(IMAGE)
    assert mib == sum(AMD64_LAYERS) / 2**20
    assert f"| linux/amd64 | {mib:.1f} MiB |" in done.stdout
