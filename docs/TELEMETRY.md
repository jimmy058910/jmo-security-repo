# Telemetry

**Status: Removed (v1.1.0).**

JMo Security no longer collects any usage telemetry. Earlier releases shipped an
opt-out telemetry module that reported anonymous, bucketed usage events, but it
was retired in v1.1.0: the tool now phones home to nothing, and no usage data
of any kind leaves your machine.

There is nothing to enable, disable, or opt out of. The former
`JMO_TELEMETRY_*` environment variables and the `telemetry:` block in `jmo.yml`
are no longer read.

- **What the tool sends now:** nothing.
- **What is stored locally:** only the scan results and history you explicitly create.
- **Privacy policy:** <https://jmotools.com/privacy>

Project adoption is tracked instead through public, external signals (PyPI
downloads, Docker Hub pulls, and GitHub stars/traffic) that require no
in-tool instrumentation.
