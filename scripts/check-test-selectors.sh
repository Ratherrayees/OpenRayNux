#!/usr/bin/env bash
# Every `--test NAME` in a developer-facing lane must name a real integration target,
# and every nextest `-E FILTER` must select at least one test. A stale selector fails
# before the suite starts, which is indistinguishable from an empty but green lane.
#
# This is the guard TEST-002 asked for. It deliberately reads the lane scripts rather
# than a hand-maintained copy: a new selector is checked by being written down once.
set -euo pipefail

cd "$(dirname "$0")/.."

bad=0

check_target() {
  local pkg="$1" target="$2" source="$3"
  local bins
  if ! bins="$(cargo nextest list -p "$pkg" --list-type binaries-only 2>/dev/null)"; then
    printf 'selector error: %s: cannot list targets for %s\n' "$source" "$pkg" >&2
    bad=1
    return
  fi
  if ! grep -qxF "$pkg::$target" <<<"$bins"; then
    printf 'selector error: %s: %s has no --test target %s\n' "$source" "$pkg" "$target" >&2
    bad=1
  fi
}

check_filter() {
  local pkg="$1" filter="$2" source="$3"
  local selected
  if ! selected="$(cargo nextest list -p "$pkg" -E "$filter" 2>/dev/null)"; then
    printf 'selector error: %s: invalid nextest filter for %s: %s\n' "$source" "$pkg" "$filter" >&2
    bad=1
    return
  fi
  if ! grep -q '::' <<<"$selected"; then
    printf 'selector error: %s: filter selects no tests in %s: %s\n' "$source" "$pkg" "$filter" >&2
    bad=1
  fi
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
