#!/usr/bin/env bash
# Every `--test NAME` in a developer-facing lane must name a real integration target,
# and every nextest `-E FILTER` must select at least one test. A stale selector fails
# before the suite starts, which is indistinguishable from an empty but green lane.
#
# This is the guard TEST-002 asked for. It deliberately reads the lane scripts rather
# than a hand-maintained copy: a new selector is checked by being written down once.
#
# The listing is nextest's JSON, not its human-readable output. Presentation output
# is colourised when CI forces CARGO_TERM_COLOR=always, which is exactly what made
# the old exact-text comparison fail while every target existed.
set -euo pipefail

cd "$(dirname "$0")/.."

bad=0

check_target() {
  python3 scripts/check-test-selectors.py target "$1" "$2" "$3" || bad=1
}

check_filter() {
  python3 scripts/check-test-selectors.py filter "$1" "$2" "$3" || bad=1
}

while IFS= read -r line; do
  if [[ "$line" =~ -p[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]+--test[[:space:]]+([A-Za-z0-9_/-]+) ]]; then
    check_target "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$line"
  fi
  if [[ "$line" =~ -p[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]+-E[[:space:]]+\"?([^\"\\]+) ]]; then
    check_filter "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$line"
  fi
done < <(grep -hE '(cargo .*--test|^[[:space:]]*"-p )' \
  scripts/run-sandbox-tests.sh \
  scripts/run-sandbox-tests-inner.sh \
  scripts/run-resource-tests.sh)

if [ "$bad" -ne 0 ]; then
  exit 1
fi
printf 'test selectors: all lane targets and filters resolve\n'
