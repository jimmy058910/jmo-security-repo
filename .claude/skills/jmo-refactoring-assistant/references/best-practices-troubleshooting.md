# Best Practices and Troubleshooting

---

## Best Practices

### Before Refactoring

1. **Commit current work:** `git commit -am "checkpoint before refactoring"`
2. **Run tests:** `make test` (ensure baseline is green)
3. **Check coverage:** `pytest --cov` (note current %)
4. **Review agent findings:** Know what you're fixing
5. **Check for circular import risks:** find who imports the module you are about
   to split. Substitute its bare module name — `target_file` below is a shell
   variable, not a literal to search for:

   ```bash
   MODULE=wizard_generators   # bare module name of the file under refactor
   git grep -n -E "^(from|import).*\b${MODULE}\b" -- 'scripts/**/*.py' 'tests/**/*.py'
   ```

   Scope it to paths and let git walk the index. A bare `grep -r "from.*import"`
   over this repository descends into `.venv/`, `results/` and `graphify-out/`
   and exceeds the agent Bash tool's 120-second timeout; the scoped form above
   returns in **0.06s**.

### During Refactoring

1. **Review before applying:** there is no preview mode — edits land directly, so
   the pre-refactor commit plus `git diff` is your dry run
2. **One refactor at a time:** Don't combine multiple refactor types
3. **Use TYPE_CHECKING for type hints:** Avoids circular imports
4. **Apply parameter injection:** Pass dependencies explicitly
5. **Verify tests frequently:** Run `pytest -x` after each file
6. **Review generated code:** Skill is 90% accurate, manual review needed
7. **Fix linting immediately:** `ruff check --fix` catches unused imports

### After Refactoring

1. **Run full test suite:** `make test`
2. **Check coverage:** compare against the percentage you noted in step 3 above —
   it should be **unchanged**. Behaviour-preserving refactoring does not move
   coverage; a drop means tests stopped exercising the moved code, most often a
   mock aimed at the wrong namespace (see test-migration-patterns.md Pattern 2).
   Diff the number yourself: neither `make test` nor CI applies a
   `--cov-fail-under` floor that would catch this for you
3. **Run linters:** `make lint` or `ruff check && black --check`
4. **Manual smoke test:** Verify key workflows still work
5. **Update docstrings:** Note refactoring and cross-references
6. **Commit with descriptive message:**

   ```bash
   git add .
   git commit -m "refactor(core): split compliance_mapper (Task 3.5)

   - Extract framework data -> compliance_frameworks.py (912 lines)
   - Reduce compliance_mapper.py 1,278 -> 399 lines (69% reduction)
   - Maintain 100% test coverage (89/89 tests passing)
   - Zero circular imports

   Fixes: Code Quality Task 3.5 (File Length Cleanup)"
   ```

---

## Troubleshooting

### "ImportError: circular import"

**Cause:** Direct imports between extracted module and source module

**Fix:**

1. Use TYPE_CHECKING pattern for type hints
2. Pass dependencies as parameters instead of importing
3. If needed, create third module for shared data

**Example:** Task 3.6 wizard.py -> wizard_generators.py

### "TypeError: missing required positional argument"

**Cause:** Function signature changed but call sites not updated

**Fix:**

1. Find all callers: `grep -r "function_name(" .`
2. Update each call site to pass new parameters
3. Update test files to pass parameters

**Example:** Task 3.6 generate_makefile_target(config, command)

### "F401: imported but unused"

**Cause:** Old imports not cleaned up after extraction

**Fix:** Run `ruff check --fix scripts/cli/wizard.py`

**Prevention:** Always run linter after refactoring

### "Tests failing after refactoring"

**Cause:** Mock objects not updated

**Fix:** Review test failures, update mocks to use new imports. Also check for missing parameters in mock calls.

### "Import errors after split_file"

**Cause:** Circular dependencies

**Fix:** Ask for the proposed module split *before* any file is written, resolve
the cycles on paper, then apply. Use TYPE_CHECKING + parameter injection patterns.

### "Coverage decreased"

**Cause:** New code paths not tested — or an existing test stopped reaching the
moved code because its `@patch` target no longer resolves in the caller's
namespace (test-migration-patterns.md Pattern 2). Rule out the second before
writing new tests for the first; a silently-inert mock looks identical to an
untested path in the coverage report.

**Fix:** Use jmo-test-fabricator to generate tests for genuinely new modules

### "Skill suggesting wrong split points"

**Cause:** Complex function boundaries

**Fix:** Ask for the proposed split as a plan, review it, and give feedback before
applying — then `git diff` against the pre-refactor commit to confirm what landed

### Common Import Errors Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: circular import` | Runtime circular dependency | Use TYPE_CHECKING or parameter injection |
| `NameError: name 'X' is not defined` | Missing import after extraction | Add import from new module |
| `TypeError: missing required positional argument` | Function signature changed | Update call sites with new parameters |
| `F401: imported but unused` | Old import not cleaned up | Run `ruff check --fix` |
