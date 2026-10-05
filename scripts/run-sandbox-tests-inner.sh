#!/usr/bin/env bash
#
# The inside of the Tier-1 sandbox container. Mounted and executed by
# `run-sandbox-tests.sh`; not meant to be run directly.
#
# It exists as its own file because the alternative is a second shell nested inside a
# double-quoted `docker run` argument, where a `$(...)` or a quote is a quoting bug
# waiting to happen -- and two of those shipped and were caught only by CI.
#
# Runs as an unprivileged uid with every capability dropped, so `bwrap` has to create a
# nested user namespace exactly as it would on a user's desktop. See
# `run-sandbox-tests.sh` for the measured reason that does not happen on a GitHub-hosted
# runner, and for what this script does instead.

set -euo pipefail

export PATH="/usr/local/cargo/bin:$PATH"

# The suites whose subject is Tier-1 sandboxed execution.
#
# `orxnud-platform-sandbox`'s `enforcement` and `resources` binaries are deliberately not
# here: they assert cgroup ceilings bite, which needs *delegation*, which needs
# CAP_SYS_ADMIN -- the configuration ADR-0046 rejects as evidence about the sandbox. Their
# home is `scripts/run-resource-tests.sh`, which explains why delegation is not a
# sandbox-privilege question.
SUITES=(
  "-p orxnud-capability --test governed_path"
  "-p orxnud-capability --test read_text_real"
  "-p orxnud-capability --test write_text"
  "-p orxnud-platform-sandbox --test isolation"
  "-p orxnuctl --test cli_e2e"
)

echo "== Tier-1 sandbox lane, inside the container =="
echo "   uid:    $(id -u)/$(id -g)"
echo "   CapEff: $(grep CapEff /proc/self/status | cut -f2)"
echo

echo "-- preflight: can this environment isolate a Tier-1 capability at all? --"
if ! cargo run -q -p orxnud-platform-sandbox --example preflight -- --check; then
  cat <<'NOTE'
========================================================================
NO POSITIVE TIER-1 EVIDENCE WAS PRODUCED BY THIS RUN.

This environment cannot create an unprivileged user namespace, so a Tier-1
capability is refused here -- correctly, by design (ADR-0035, V-49). Nothing was
weakened to make that happen, and no suite below was run or skipped silently.

Where the positive evidence comes from instead:
  * scripts/run-sandbox-tests.sh --host   on a host that can create one
  * scripts/run-sandbox-tests.sh          in a container, on such a host
  * scripts/run-resource-tests.sh         for cgroup-enforcement suites, which
                                          need delegation and so a different
                                          container again

The preflight output above is the record. This job exists to keep that measurement
visible on every run, not to prove the sandbox.
========================================================================
NOTE
  exit 0
fi

# It can isolate. Now insist the configuration is the production one before treating any
# green suite here as evidence about the path users run -- a container that already holds
# CAP_SYS_ADMIN would pass every suite while exercising nothing a user ever executes.
echo
echo "-- it can isolate; now asserting the production configuration --"
cargo run -q -p orxnud-platform-sandbox --example preflight -- --require

echo
echo "-- Tier-1 suites --"
for suite in "${SUITES[@]}"; do
  # shellcheck disable=SC2086 # the suite is intentionally several words
  cargo nextest run $suite --no-fail-fast
  echo
done
