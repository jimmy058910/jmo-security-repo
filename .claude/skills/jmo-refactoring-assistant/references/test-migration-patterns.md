# Test Migration Patterns

Patterns for updating tests when refactoring moves code between modules.

---

## Pattern 1: Direct Import Split

**When tests import extracted functions directly:**

```python
# tests/cli/test_wizard.py

# BEFORE
from wizard import generate_makefile_target

def test_generate_makefile_target():
    makefile = generate_makefile_target(config)
    assert "jmotools" in makefile

# AFTER
from wizard import generate_command  # Keep helper in original module
from wizard_generators import generate_makefile_target  # Import from new module

def test_generate_makefile_target():
    command = generate_command(config)  # Generate dependency
    makefile = generate_makefile_target(config, command)  # Pass parameter
    assert "jmotools" in makefile
```

---

## Pattern 2: Mock Update

**When tests mock extracted functions:** patch the namespace the *caller* looks
the name up in, which is usually **not** the module the function moved to.

Extraction leaves the source module importing the function back:

```python
# scripts/cli/wizard.py:119 -- the real shape after Task 3.6
from scripts.cli.wizard_generators import generate_makefile_target
```

That `from X import Y` binds a **second** name, `wizard.generate_makefile_target`,
and `run_wizard` resolves through it. Replacing the definition in
`wizard_generators` leaves that binding untouched, so the mock never fires.

```python
# BEFORE -- and still correct when the test exercises run_wizard()
@patch("wizard.generate_makefile_target")
def test_run_wizard_emit_make(mock_gen):
    ...

# WRONG after extraction: patches the definition, not the name run_wizard calls
@patch("wizard_generators.generate_makefile_target")
def test_run_wizard_emit_make(mock_gen):
    ...  # mock_gen is never called; the real function runs
```

**Measured**, on a two-module reproduction of the shape above:

| Patch target | `run_wizard()` returns |
|--------------|------------------------|
| `wizard_generators.generate_makefile_target` | `REAL` -- patch is a no-op |
| `wizard.generate_makefile_target` | `MOCKED` |

Patch `wizard_generators.X` only when the test calls into `wizard_generators`
directly, or when the caller kept a module reference (`import wizard_generators`
then `wizard_generators.X()`), which resolves the attribute at call time.

**Rule:** the patch target follows the *caller's* import style, not the
function's new home. A move that changes Pattern 1's import path usually leaves
Pattern 2's patch target exactly where it was.

---

## Pattern 3: Integration Test Update

**When tests use functions through public API:**

```python
# BEFORE
from wizard import run_wizard

def test_wizard_generates_makefile(tmp_path):
    rc = run_wizard(emit_make="Makefile.test")
    assert rc == 0
    # No changes needed - function called through run_wizard()
```

**Key Insight:** Integration tests are more resilient to refactoring!

---

## Test Migration Checklist

- [ ] Identify all files importing extracted functions (`grep -r "from wizard import"`)
- [ ] Split imports between old and new modules
- [ ] Update function calls with new parameters
- [ ] Re-check mock targets against the *caller's* namespace (Pattern 2) -- a
      test that mocks a call made inside `wizard` keeps `@patch("wizard.X")`
- [ ] Confirm each mock still fires (assert on `mock.called`, not just on the
      return value -- a patch aimed at the wrong namespace fails silently)
- [ ] Run tests after each file: `pytest tests/cli/test_wizard.py -xvs`
- [ ] Verify no `TypeError: missing required positional argument` errors
- [ ] Check coverage hasn't decreased: `pytest --cov` (compare against the
      baseline captured before refactoring; there is no threshold flag to rely on)
