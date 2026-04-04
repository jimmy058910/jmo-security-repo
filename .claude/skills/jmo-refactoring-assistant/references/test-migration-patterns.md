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

**When tests mock extracted functions:**

```python
# BEFORE
@patch("wizard.generate_makefile_target")
def test_run_wizard_emit_make(mock_gen):
    ...

# AFTER
@patch("wizard_generators.generate_makefile_target")  # Update module path
def test_run_wizard_emit_make(mock_gen):
    ...
```

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
- [ ] Update mock paths (`@patch("wizard.X")` -> `@patch("wizard_generators.X")`)
- [ ] Run tests after each file: `pytest tests/cli/test_wizard.py -xvs`
- [ ] Verify no `TypeError: missing required positional argument` errors
- [ ] Check coverage hasn't decreased: `pytest --cov`
