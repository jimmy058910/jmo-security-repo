"""First-run bookkeeping and the MCP server's stdin (#931, #958, #875).

Three defects that share a shape: code in `scripts/cli/jmo.py` that reads or
writes state belonging to something else.

* #958 -- `jmo mcp-server` prompted on stdin, which on that path IS the MCP
  client's JSON-RPC pipe, so it ate the `initialize` handshake before failing.
* #931 -- the first-run flow rewrote `~/.jmo/config.yml` from scratch on every
  branch, discarding keys it does not set, and carried an `except ImportError`
  that could never fire and claimed success if it had.
* #875 -- `wizard.py` declared a `__version__` three releases behind `jmo.py`'s,
  which nothing read.
"""

from __future__ import annotations

import io
import sys

import pytest
import yaml

import scripts.cli.jmo as jmo

# ==========================================================================
# #958 -- mcp-server must not read the transport's stdin
# ==========================================================================


class _PipeStdin(io.StringIO):
    """stdin as an MCP client provides it: a pipe with data already waiting."""

    def isatty(self) -> bool:
        return False


class _TtyStdin(io.StringIO):
    def isatty(self) -> bool:
        return True


INITIALIZE = (
    '{"jsonrpc":"2.0","id":0,"method":"initialize",'
    '"params":{"protocolVersion":"2024-11-05"}}\n'
)
INITIALIZED = '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'


@pytest.fixture
def piped_stdin(monkeypatch):
    fake = _PipeStdin(INITIALIZE + INITIALIZED)
    monkeypatch.setattr(sys, "stdin", fake)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.delenv("JMO_NON_INTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    return fake


def test_the_clients_first_message_is_not_consumed(piped_stdin):
    """The regression.

    A pipe with data does NOT raise EOFError -- `input()` succeeds and returns
    the client's message. So the pre-existing `except (EOFError,
    KeyboardInterrupt)` could not help; only refusing to read can.
    """
    jmo._prompt_install_dependency("mcp_missing")

    remaining = piped_stdin.read()
    assert INITIALIZE in remaining, (
        "the MCP client's initialize request was consumed by an install prompt; "
        f"what is left in the pipe is {remaining!r}"
    )
    assert INITIALIZED in remaining


def test_it_declines_rather_than_installing_on_a_pipe(piped_stdin):
    assert jmo._prompt_install_dependency("mcp_missing") is False


def test_it_says_how_to_install_instead(monkeypatch, capsys):
    """Declining silently would trade one confusing symptom for another.

    Uses capsys rather than swapping sys.stderr for a StringIO: pytest's own
    capture owns that attribute, and a fixture-level patch of it loses.
    """
    monkeypatch.setattr(sys, "stdin", _PipeStdin(INITIALIZE + INITIALIZED))
    monkeypatch.delenv("JMO_NON_INTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)

    jmo._prompt_install_dependency("mcp_missing")

    err = capsys.readouterr().err
    assert "pip install" in err
    assert "mcp" in err


@pytest.mark.parametrize("dep", ["mcp_missing", "pydantic_v1"])
def test_neither_dependency_path_reads_the_pipe(piped_stdin, dep):
    """Both branches build a different `package`; both must stay off stdin."""
    jmo._prompt_install_dependency(dep)
    assert INITIALIZE in piped_stdin.read()


def test_a_real_terminal_is_still_prompted(monkeypatch):
    """The negative control.

    "Never read stdin" would also pass every test above and would silently
    delete the feature for the human it was written for.
    """
    monkeypatch.setattr(sys, "stdin", _TtyStdin("n\n"))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.delenv("JMO_NON_INTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)

    asked: list[str] = []

    def _fake_input(prompt: str = "") -> str:
        asked.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", _fake_input)

    jmo._prompt_install_dependency("mcp_missing")
    assert asked, "an interactive terminal was not prompted at all"
    assert "Install" in asked[0]


@pytest.mark.parametrize("var", ["JMO_NON_INTERACTIVE", "CI"])
def test_the_conventional_env_guards_are_honoured(monkeypatch, var):
    """Matches the guard the file's other prompt sites already use."""
    monkeypatch.setattr(sys, "stdin", _TtyStdin("y\n"))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.delenv("JMO_NON_INTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv(var, "1")

    def _boom(prompt: str = "") -> str:
        raise AssertionError(f"prompted despite {var} being set: {prompt!r}")

    monkeypatch.setattr("builtins.input", _boom)
    assert jmo._prompt_install_dependency("mcp_missing") is False


# ==========================================================================
# #931 -- first-run config writes must merge, not clobber
# ==========================================================================


def test_update_jmo_config_preserves_keys_it_does_not_set(tmp_path):
    """The measured case: a real config on the maintainer's machine held
    `scan_count: 685`, and the invalid-email branch wrote
    `{onboarding_completed: True}` over it."""
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "scan_count: 685\nemail: keep@me.com\ncustom_key: value\n", encoding="utf-8"
    )

    jmo._update_jmo_config(cfg, {"onboarding_completed": True})

    got = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert got["scan_count"] == 685
    assert got["email"] == "keep@me.com"
    assert got["custom_key"] == "value"
    assert got["onboarding_completed"] is True


def test_update_jmo_config_overwrites_the_keys_it_does_set(tmp_path):
    """Merging must not become "never change anything"."""
    cfg = tmp_path / "config.yml"
    cfg.write_text("email: old@example.com\n", encoding="utf-8")

    jmo._update_jmo_config(cfg, {"email": "new@example.com"})

    got = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert got["email"] == "new@example.com"


def test_update_jmo_config_creates_the_file_when_absent(tmp_path):
    cfg = tmp_path / "nested" / "config.yml"
    jmo._update_jmo_config(cfg, {"onboarding_completed": True})
    assert yaml.safe_load(cfg.read_text(encoding="utf-8")) == {
        "onboarding_completed": True
    }


def test_update_jmo_config_never_raises_on_unreadable_content(tmp_path):
    """First-run bookkeeping must not take down the scan that triggered it."""
    cfg = tmp_path / "config.yml"
    cfg.write_text("this: is: not: valid: yaml:\n", encoding="utf-8")
    jmo._update_jmo_config(cfg, {"onboarding_completed": True})
    assert yaml.safe_load(cfg.read_text(encoding="utf-8"))["onboarding_completed"]


def test_update_jmo_config_survives_a_config_that_is_not_a_mapping(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("- a\n- b\n", encoding="utf-8")
    jmo._update_jmo_config(cfg, {"onboarding_completed": True})
    assert yaml.safe_load(cfg.read_text(encoding="utf-8")) == {
        "onboarding_completed": True
    }


def test_no_first_run_branch_claims_success_without_sending(tmp_path, monkeypatch):
    """#931's headline: the dead `except ImportError` printed "You're all set."

    Asserted as a property of the *output* rather than by grepping the source,
    so it keeps holding however the branches are arranged. Drives the flow with
    a subscribe that fails, which is what every user without RESEND_API_KEY
    actually gets.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(jmo.Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr(sys, "stdin", _TtyStdin("user@example.com\n"))
    monkeypatch.setattr("builtins.input", lambda *a, **k: "user@example.com")
    monkeypatch.delenv("JMO_NON_INTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DOCKER_CONTAINER", raising=False)

    import scripts.core.email_service as es

    monkeypatch.setattr(es, "validate_email", lambda e: True)
    monkeypatch.setattr(es, "subscribe_to_newsletter", lambda *a, **k: (False, False))

    printed: list[str] = []
    monkeypatch.setattr(jmo, "_safe_print", lambda s: printed.append(str(s)))
    monkeypatch.setattr(
        "builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a)))
    )

    class _Args:
        log_level = None
        human_logs = False

    jmo._collect_email_opt_in(_Args())

    out = " ".join(printed)
    assert (
        "You're all set" not in out
    ), f"a path that sent nothing told the user they were all set: {out!r}"
    assert (
        "subscribe.html" in out
    ), "a failed signup must point somewhere the user can actually finish"


# ==========================================================================
# #875 -- one version, in one place
# ==========================================================================


def test_wizard_declares_no_version():
    """It declared 1.0.5 against jmo.py's 1.0.8 and nothing read it. A second
    declaration nobody consults can only ever be wrong or redundant."""
    import scripts.cli.wizard as wizard

    assert not hasattr(wizard, "__version__"), (
        "wizard.py declared a __version__ again. The version lives in "
        "scripts/cli/jmo.py; call scripts.core.jmo_version.get_jmo_version() "
        "if you need it at runtime."
    )


def test_jmo_still_declares_the_version_the_validator_reads():
    """release_validator regex-extracts __version__ out of jmo.py, so removing
    the wizard's copy must not have been mistaken for removing the real one."""
    assert isinstance(jmo.__version__, str)
    assert jmo.__version__.count(".") == 2, jmo.__version__


def test_no_other_cli_module_declares_a_rival_version():
    """Guards the class, not the one file that had it."""
    import ast
    import pathlib

    offenders: list[str] = []
    for path in sorted(pathlib.Path("scripts/cli").glob("*.py")):
        if path.name == "jmo.py":
            continue
        tree = ast.parse(path.read_bytes().decode("utf-8"))
        for node in tree.body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target] if isinstance(node, ast.AnnAssign) else []
            )
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "__version__":
                    offenders.append(f"{path.as_posix()}:{node.lineno}")

    assert not offenders, (
        f"a second __version__ appeared at {offenders}; it will drift from "
        f"jmo.py's the way wizard.py's did (#875)"
    )
