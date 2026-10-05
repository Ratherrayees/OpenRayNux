#!/usr/bin/env bash
#
# Reports whether this machine can isolate a Tier-1 subprocess, and whether the sandbox
# that can is the *production* one.
#
# The judgement is delegated entirely to
# `cargo run -p orxnud-platform-sandbox --example preflight`, which uses the same probe
# and the same `AvailableGuarantees::check` the dispatcher uses. This script exists only
# so CI and a developer invoke it the same way and so the answer appears in build logs
# rather than having to be inferred from a red test.
#
# `--require` exits non-zero unless a Tier-1 capability can be sandboxed here *and* the
# observed identity is the nested-user-namespace shape. Use it in a lane whose purpose is
# to execute Tier-1 work: that lane must fail loudly, never run a reduced suite and pass.

set -euo pipefail

cd "$(dirname "$0")/.."

cargo run -q -p orxnud-platform-sandbox --example preflight -- "$@"
