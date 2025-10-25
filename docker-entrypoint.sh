#!/bin/bash
# Docker entrypoint for JMo Security
# Adds telemetry notice banner before running jmo

# Show telemetry banner (opt-out model) if not disabled
if [ "$JMO_TELEMETRY_DISABLE" != "1" ]; then
    echo "" >&2
    echo "=====================================================================" >&2
    echo "📊 JMo Security collects anonymous usage stats (opt-out anytime)" >&2
    echo "=====================================================================" >&2
    echo "No repo names, secrets, or personal data is collected." >&2
    echo "" >&2
    echo "💡 Opt-out: docker run -e JMO_TELEMETRY_DISABLE=1 ..." >&2
    echo "📄 Privacy: https://jmotools.com/privacy" >&2
    echo "=====================================================================" >&2
    echo "" >&2
fi

# Execute jmo with all arguments
exec jmo "$@"
