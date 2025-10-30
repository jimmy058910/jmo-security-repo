# Contributors

Thank you to everyone who has contributed to JMo Security Audit Tool Suite! This project thrives because of our amazing community.

## Code Contributors

Listed in chronological order of first contribution:

### @iclectic

- **Hadolint Dockerfile Linting Integration** ([#2](https://github.com/jimmy058910/jmo-security-repo/pull/2))
  - Added Hadolint to CI for Dockerfile best practices validation
  - Integrated linting checks for all 3 Docker variants (full/slim/alpine)
  - Impact: Improved container security and build quality

### @ADITYABHURAN

- **SARIF Schema Validation** ([#97](https://github.com/jimmy058910/jmo-security-repo/pull/97), closes [#87](https://github.com/jimmy058910/jmo-security-repo/issues/87))
  - Added SARIF 2.1.0 schema validation to CI workflow
  - Python-based validation using Microsoft SARIF SDK schema
  - Optimized CI by moving validation to quick-checks job (6x efficiency gain)
  - Impact: Ensures SARIF output compliance with industry standards

## How to Contribute

We welcome contributions of all kinds! Here's how to get started:

### First-Time Contributors

1. **Find an Issue**: Look for issues tagged [`good first issue`](https://github.com/jimmy058910/jmo-security-repo/labels/good%20first%20issue) or [`help wanted`](https://github.com/jimmy058910/jmo-security-repo/labels/help%20wanted)
2. **Read the Guides**:
   - [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup and workflow
   - [CLAUDE.md](CLAUDE.md) - Project architecture and conventions
   - [TEST.md](TEST.md) - Testing guidelines
3. **Ask Questions**: Comment on the issue before starting work to clarify requirements
4. **Submit PR**: Follow the PR template and link the issue you're addressing

### Types of Contributions

We value contributions in many forms:

- **Code**: Bug fixes, new features, performance improvements
- **Documentation**: Guides, examples, API docs, typo fixes
- **Testing**: Unit tests, integration tests, test coverage improvements
- **Security**: Tool integrations, vulnerability fixes, security audits
- **Community**: Answering questions, triaging issues, reviewing PRs

### Recognition

Contributors are recognized in:

- This CONTRIBUTORS.md file
- Release notes in [CHANGELOG.md](CHANGELOG.md)
- PR merge comments with detailed acknowledgment
- GitHub contributor graphs and stats

## Project Maintainers

- **@jimmy058910** - Project Creator & Lead Maintainer

## Questions?

- **Issues**: [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
- **Documentation**: [docs/index.md](docs/index.md)

Thank you for making JMo Security better! 🚀
