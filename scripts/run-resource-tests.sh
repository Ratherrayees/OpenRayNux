#!/usr/bin/env bash
#
# Resource-enforcement tests, in a delegated cgroup v2 environment.
#
# # Why a separate runner
#
# The development host does not delegate cgroup controllers: `memory.max`,
# `pids.max` and `cpu.max` all return EPERM in a cgroup created under the user's own
# scope, while the controllers *appear* in `cgroup.controllers`. Those are different
# facts, and only the second one matters (V-46).
#
# A container with the cgroup filesystem mounted read-write *does* get delegation, and
# that is verified on this host. So the resource tests run there, unmodified, and the
# developer's session is left alone — changing a desktop session's cgroup delegation to
# make a test pass would be a system-wide configuration change for a test's benefit.
#
# # Usage
#
#   scripts/run-resource-tests.sh            # container
#   scripts/run-resource-tests.sh --native   # run directly, reporting NOT_PROVEN
#
# # Current standing (Phase 4b, measured)
#
# In the delegated container this script demonstrates:
#   * memory.max, memory.swap.max, pids.max, cpu.max and cgroup.kill are all WRITABLE
#   * `cgroup_kill_terminates_a_member_that_forked_a_descendant` PASSES
#
# It does NOT yet demonstrate memory/pids/cpu *enforcement* end to end, because the
# cgroup directory the probe selects inside `rust:1-bookworm` is not one it can create
# children in. That gap is recorded as V-46 rather than papered over: the controls are
# writable, which is necessary and not sufficient. `alpine` was verified to accept a
# subdirectory at the hierarchy root, so the remaining work is directory selection, not
# a missing kernel capability.
#
# # What it does and does not prove
#
# Proves, in the container: memory.max enforcement, pids.max enforcement, cpu.max
# throttling, and cgroup.kill subtree termination.
# Does NOT prove: anything about the developer's own session, and nothing about
# Windows (see run-windows-tests.sh and V-29).

set -euo pipefail

cd "$(dirname "$0")/.."

# `rust:1-bookworm` rather than `rust:latest`, so the toolchain a resource test
# runs against is pinned by tag rather than by whatever is newest that week.
IMAGE="${ORXNUD_RESOURCE_IMAGE:-rust:1-bookworm}"
MOUNT_CGROUP="${ORXNUD_MOUNT_CGROUP:-/sys/fs/cgroup}"

if [ "${1:-}" = "--native" ]; then
  echo "== resource tests, native (no delegation expected) =="
  # Reports NOT_PROVEN per control rather than skipping. A skip teaches nothing.
  cargo test -p orxnud-platform-sandbox --test resources -- --nocapture --test-threads=1
  exit $?
fi

echo "== resource tests, delegated cgroup v2 =="
echo "   image:   $IMAGE"
echo "   cgroup:  $MOUNT_CGROUP (read-write)"

# `--privileged` is required for cgroup delegation: writing a controller file needs
# CAP_SYS_ADMIN over the hierarchy, and the kernel refuses without it. The container
# is disposable and holds nothing but the test binaries.
#
# `--cgroupns=host` is just as required, and for a subtler reason. Docker otherwise
# gives the container a *private cgroup namespace*, so the PIDs it reports do not
# match the hierarchy at /sys/fs/cgroup. Writing a PID to `cgroup.procs` then fails
# with ENOENT -- the process "does not exist" as far as the host hierarchy is
# concerned -- even though the directory and the file are both plainly there. Sharing
# the cgroup namespace makes the PID spaces agree. Found by running the test and
# getting ENOENT from an obviously-correct path.
docker run --rm \
  --privileged \
  --cgroupns=host \
  -v "$PWD":/src \
  -v "$MOUNT_CGROUP":/sys/fs/cgroup:rw \
  -w /src \
  -v orxnud-cargo-registry:/usr/local/cargo/registry \
  -v orxnud-target:/src/target \
  "$IMAGE" \
  bash -lc '
    set -e
    export PATH="/usr/local/cargo/bin:$PATH"
    echo "cargo: $(command -v cargo || echo MISSING)"
    echo "--- environment ---"
    stat -fc "cgroup fs type: %T" /sys/fs/cgroup
    echo "controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null | tr "\n" " ")"
    cargo test -p orxnud-platform-sandbox --test resources -- --nocapture --test-threads=1
    cargo test -p orxnud-capability --test governed_path -- --test-threads=1
  '
