# Technology Stack - JMo Security Audit Tool Suite


## Python Backend (Security Engine)

- **Language:** Python 3.10+ (Tested on 3.10, 3.11, 3.12)

- **CLI Framework:** `argparse` + `rich` (Progress bars, tables, panels)

- **Configuration:** `PyYAML` (For `jmo.yml` loading)

- **Orchestration:** `subprocess` (shell=False) + `threading` (Parallel tool execution)

- **Storage:** `sqlite3` (Historical persistence), `json`/`sarif` (Normalized outputs)

- **Deduplication:** `rapidfuzz` (Fuzzy matching for cross-tool findings)

- **Statistics:** `scipy` + `numpy` (Mann-Kendall trend analysis)

- **Scheduling:** `croniter` (Cron expression parsing for scheduled scans)

- **Validation:** `jsonschema` (Validation against CommonFinding schema v1.2.0)


## React Dashboard (Reporting UI)

- **Framework:** React 18.2 + TypeScript 5.2

- **Build Tool:** Vite 5.1 + `vite-plugin-singlefile` (Self-contained HTML reports)

- **Styling:** Tailwind CSS 3.4 + PostCSS + Autoprefixer

- **Charts:** Recharts 2.15

- **UI Components:** Radix UI (Tooltips), Lucide React (Icons)

- **Testing:** Jest 30 + React Testing Library


## Quality & Development Tooling

- **Formatting:** Black (Primary), Ruff (Secondary)

- **Linting:** Ruff (Fast, Rust-based linting)

- **Type Checking:** `mypy` (Python), `tsc` (TypeScript)

- **Security:** Bandit (SAST scanning on the project's own codebase)

- **Testing Frameworks:**
  - `pytest` + `pytest-cov` (Coverage reporting)
  - `pytest-xdist` (Parallel test execution)
  - `pytest-timeout` (Safety net, 120s default)
  - `pytest-split` (CI sharding across 4 parallel jobs)
  - `hypothesis` (Property-based testing)

- **VCS Hooks:** `pre-commit` (Enforcing Black ? Ruff ordering)
