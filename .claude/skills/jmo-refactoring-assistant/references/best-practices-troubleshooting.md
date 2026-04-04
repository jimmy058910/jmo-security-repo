# Best Practices and Troubleshooting

---

## Best Practices

### Before Refactoring

1. **Commit current work:** `git commit -am "checkpoint before refactoring"`
2. **Run tests:** `make test` (ensure baseline is green)
3. **Check coverage:** `pytest --cov` (note current %)
4. **Review agent findings:** Know what you're fixing
5. **Check for circular import risks:** `grep -r "from.*import" | grep target_file`

### During Refactoring

1. **Start with --dry-run:** Preview changes before applying
2. **One refactor at a time:** Don't combine multiple refactor types
3. **Use TYPE_CHECKING for type hints:** Avoids circular imports
4. **Apply parameter injection:** Pass dependencies explicitly
5. **Verify tests frequently:** Run `pytest -x` after each file
6. **Review generated code:** Skill is 90% accurate, manual review needed
7. **Fix linting immediately:** `ruff check --fix` catches unused imports

### After Refactoring

1. **Run full test suite:** `make test`
2. **Check coverage:** Should be >= before
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

**Fix:** Use `--dry-run` to preview, manually resolve circular imports before applying. Use TYPE_CHECKING + parameter injection patterns.

### "Coverage decreased"

**Cause:** New code paths not tested

**Fix:** Use jmo-test-fabricator to generate tests for new modules

### "Skill suggesting wrong split points"

**Cause:** Complex function boundaries

**Fix:** Use `--dry-run`, review proposed split, provide feedback for manual refinement

### Common Import Errors Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: circular import` | Runtime circular dependency | Use TYPE_CHECKING or parameter injection |
| `NameError: name 'X' is not defined` | Missing import after extraction | Add import from new module |
| `TypeError: missing required positional argument` | Function signature changed | Update call sites with new parameters |
| `F401: imported but unused` | Old import not cleaned up | Run `ruff check --fix` |
