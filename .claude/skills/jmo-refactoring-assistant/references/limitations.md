# Limitations and Edge Cases

---

## What This Skill Does NOT Do

1. **Logic changes:** Only structural refactoring, no behavior changes
2. **Algorithm improvements:** Doesn't optimize performance
3. **API changes:** Preserves public interfaces
4. **Cross-project refactoring:** JMo Security-specific patterns only
5. **Automatic circular import detection:** Manual review still needed

---

## Known Edge Cases

1. **Dynamic imports:** May not detect `importlib.import_module()` usage
2. **Monkeypatching:** Can't handle runtime modifications
3. **Complex decorators:** May need manual adjustment
4. **Circular dependencies:** Will warn but not auto-fix (use TYPE_CHECKING pattern)
5. **Multiple inheritance:** May complicate base pattern migration
6. **Global state:** Parameter injection may expose hidden dependencies

---

## When to Use Manual Refactoring Instead

- **Small functions (<50 lines):** Overhead not worth it
- **Unclear boundaries:** Need human judgment on split points
- **Prototype code:** Not ready for structure
- **External API constraints:** Public interface can't change
- **Complex circular web:** Neither pattern fixes bad design - redesign needed
