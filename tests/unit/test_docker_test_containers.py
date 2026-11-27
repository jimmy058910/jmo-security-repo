"""The cleanup of containers started by tests (`run_container` and the sweeps
in tests/conftest.py), checked without Docker.

The Docker tests themselves cannot show it: a clean run leaves nothing either
way, and no CI job interrupts one. These pin which runs the reaper removes, and
that an interrupted `docker run` takes its container with it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests import conftest
from tests.conftest import skip_on_windows


def _exited_pid() -> int:
    """The pid of a process that has exited."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=30)
    return proc.pid


@skip_on_windows  # no reaper there: os.kill(pid, 0) would end the process
def test_the_reaper_removes_only_runs_whose_process_is_gone(monkeypatch):
    """Containers and volumes go for a run whose owner has exited. A live
    owner's stay, and so do another host's under the same run id (a pid there
    says nothing here), and a label naming no pid."""
    dead, live = _exited_pid(), os.getpid()
    calls: list[tuple[str, ...]] = []

    host_filter = f"label={conftest.DOCKER_HOST_LABEL}={socket.gethostname()}"

    def docker(*args: str, timeout: int = 120) -> str:
        calls.append(args)
        if "--format" in args:  # the run labels on this host
            return f"{dead}-aa\n{live}-bb\nnot-a-pid\n"
        if "--quiet" in args:  # the objects of one run, on this host only
            run_filter = next(a for a in args if conftest.DOCKER_RUN_LABEL in a)
            run = run_filter.rsplit("=", 1)[1]
            return f"obj-{run}\n" if host_filter in args else f"elsewhere-{run}\n"
        return ""

    monkeypatch.setattr(conftest, "_docker_quiet", docker)
    conftest._reap_dead_docker_runs()

    listings = [c for c in calls if "--format" in c]
    assert len(listings) == 2, calls  # containers, then volumes
    assert all(host_filter in c for c in listings), listings
    removals = [c for c in calls if "rm" in c[:2]]
    assert removals == [
        ("rm", "--force", "--volumes", f"obj-{dead}-aa"),
        ("volume", "rm", "--force", f"obj-{dead}-aa"),
    ]


@pytest.mark.parametrize("interruption", [subprocess.TimeoutExpired, KeyboardInterrupt])
def test_an_interrupted_docker_run_removes_its_container(monkeypatch, interruption):
    """A client killed between create and start leaves a container `--rm`
    never removes; `run_container` removes it by the name it gave it."""
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            if interruption is KeyboardInterrupt:
                raise KeyboardInterrupt
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, "", "")

    fake = SimpleNamespace(run=run, SubprocessError=subprocess.SubprocessError)
    with monkeypatch.context() as m:
        m.setattr(conftest, "subprocess", fake)
        with pytest.raises(interruption):
            conftest.run_container(["img", "--help"], timeout=5, cache=False)

    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "--force", "--volumes", name], calls


def test_every_process_of_a_run_shares_one_run_id():
    """The controller sets the run id before it starts xdist workers, so a
    worker's containers carry the controller's pid, which outlives a worker
    that crashes, and the controller's sweep finds them."""
    owner = int(os.environ[conftest._DOCKER_RUN_ENV].split("-", 1)[0])
    if os.environ.get("PYTEST_XDIST_WORKER"):
        assert owner == os.getppid()
    else:
        assert owner == os.getpid()
