"""Copy files that live outside the `scripts` package into the wheel.

Everything else about the build is declared in pyproject.toml. This exists for
the files the installed package reads but that must stay where they are in the
repository, because workflows, `scripts/dev/update_versions.py` and the
Dockerfile read them there: package-data cannot name a file outside its
package. A source checkout, the editable install and the Docker image read the
originals, so an editable build copies nothing.

The sdist carries the originals (MANIFEST.in), so a wheel built from the sdist,
as the release's `python -m build` does, gets them too.
"""

from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

# repository path -> path inside the wheel
SHIPPED = {
    # The tool pins every `jmo tools` command reads (#1511).
    "versions.yaml": "scripts/core/versions.yaml",
    # The CommonFinding schema the report validates against (#1350); docs/ is
    # its published home.
    "docs/schemas/common_finding.v1.json": "scripts/core/schemas/common_finding.v1.json",
}


HERE = Path(__file__).resolve().parent


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        if self.editable_mode:
            return
        for name, dest in SHIPPED.items():
            source = HERE / name
            if not source.is_file():
                raise SystemExit(
                    f"setup.py: {name} is missing, so the wheel would be broken"
                )
            target = Path(self.build_lib) / dest
            self.mkpath(str(target.parent))
            self.copy_file(str(source), str(target))


setup(cmdclass={"build_py": BuildPy})
