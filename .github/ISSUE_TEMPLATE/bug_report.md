---
name: Bug report
about: Create a report to help us improve
labels: bug

---

# Bug Report

## Describe the bug

A clear and concise description of what the bug is.

## Reproduction

### How are you running JMo?

- [ ] Installed CLI (`pip install jmo-security`)
- [ ] From source (`pip install -e .`)
- [ ] Docker (`ghcr.io/jimmy058910/jmo-security:<tag>` — please specify tag)
- [ ] Other (specify):

### Exact command

```bash
# paste the full command, e.g. `jmo scan --profile balanced --repo .`
```

### Scan profile (if applicable)

- [ ] `fast`
- [ ] `slim`
- [ ] `balanced`
- [ ] `deep`
- [ ] Custom profile (paste relevant `jmo.yml` snippet below)
- [ ] Not applicable

### What was scanned?

- Target type (repo / image / cloud / etc.):
- Public example or sanitized minimal repro (if shareable):

## Expected behavior

A clear and concise description of what you expected to happen.

## Actual behavior

What actually happened? Include the exact error message if any.

## Logs / Output

<!-- markdownlint-disable MD033 -->
<details>
<summary>Click to expand</summary>

```text
# paste relevant output here. If long, prefer attaching a file.
# For tool-runner errors, include the contents of results/individual-<type>/<tool>.stderr.log.
```

</details>
<!-- markdownlint-enable MD033 -->

## Environment

- OS: <!-- e.g., Ubuntu 24.04, macOS 14.5, Windows 11 -->
- Python: <!-- output of `python --version` -->
- JMo version: <!-- output of `jmo --version` -->
- Docker (if applicable): <!-- output of `docker --version` -->
- Tools installed (if relevant): <!-- output of `jmo tools check --json` (truncated to relevant tools is fine) -->

## Additional context

Add any other context about the problem here — recent changes, suspected root cause, or related issues.
