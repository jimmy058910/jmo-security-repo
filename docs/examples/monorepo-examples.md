# Monorepo Examples (JMo Security)

> Status: draft for PR #<your-issue>; branch: feat/monorepo-examples

## Scope

This document provides examples for verifying and scanning **monorepos**, which include multiple applications and shared components.
It demonstrates how to apply JMo Security’s verification wizard using both the --repos-dir and --targets options, showing how profiles (ast, alanced, and deep) can be used to adjust scan depth and performance based on workflow needs.

## Profiles

- **Fast** – Executes a high-level verification with minimal checks. Recommended for quick local validation before committing changes.
- **Balanced** – Performs a moderate-depth verification suitable for continuous integration (CI) pipelines and shared environments.
- **Deep** – Runs an exhaustive verification that examines all dependencies and configurations. Intended for pre-release validation and comprehensive security reviews.

## Examples

### Using --repos-dir

> Run a general verification scan across all repositories in a workspace directory. This approach is useful for identifying configuration or dependency issues early in development.

~~~bash
jmo-sec wizard verify --repos-dir /path/to/monorepos --profile fast
~~~

> Conduct a balanced verification pass suitable for continuous integration (CI) pipelines. This mode provides broader coverage while maintaining reasonable runtime.

~~~bash
jmo-sec wizard verify --repos-dir /path/to/monorepos --profile balanced
~~~

### Using --targets

> Perform a deep analysis on specific targets within a monorepo. This is typically used before major releases or security reviews.

~~~bash
jmo-sec wizard verify --targets app-a,app-b,packages/shared --profile deep
~~~

## Notes

- All examples were verified locally using pre-commit hooks to ensure consistent formatting and markdown compliance.
- Commands are structured for clarity and reproducibility in both local and CI environments.
- Replace example paths and target names with project-specific values when applying these commands.
