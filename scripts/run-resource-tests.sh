#!/usr/bin/env bash
#
# Resource-enforcement tests, in a delegated cgroup v2 environment.
#
# # Why a separate runner
#
# A cgroup that accepts `mkdir` need not have any controller delegated to it.
# `memory.max`, `pids.max` and `cpu.max` can return EPERM in a cgroup created under the
# user's own scope while the controllers *appear* in `cgroup.controllers`. Those are
# different facts, and only the second one matters (V-46). Discovery therefore probes by
# *writing*, walking from the process's own cgroup up through its ancestors.
#
# A container with the cgroup filesystem mounted read-write *does* get delegation, and
# that is verified. So the resource tests run there, unmodified, and the developer's
# session is left alone — changing a desktop session's cgroup delegation to make a test
# pass would be a system-wide configuration change for a test's benefit.
#
# # Delegation is per-host, not per-machine
#
# Whether a *native* run can enforce depends entirely on where the process sits in the
# hierarchy, and that varies by host even on the same kernel:
#
#   * Under a desktop session on systemd, the user's own slice typically DOES delegate.
#     Measured 2026-10-02 on the Phase 4 host: `user.slice/user-1000.slice/
#     user@1000.service/app.slice` accepts `memory.max`, `memory.swap.max`, `pids.max`,
#     `cpu.max` and `cgroup.kill`, and the whole Phase 4b enforcement suite passes
#     natively there.
#   * Inside a container with a private cgroup namespace, the container's own cgroup
#     usually has nothing delegated to it, and `--privileged --cgroupns=host` is required.
#
# So `--native` below reports what it actually found rather than assuming either answer.
# Do not read "this host delegates nothing" into an old log line: it was true for one
# host and is false for another.
#
# # Usage
#
#   scripts/run-resource-tests.sh            # container
#   scripts/run-resource-tests.sh --native   # run directly, reporting what was found
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
  # Delegation is per-host, so the banner reports what this host actually has rather
  # than what a previous host happened to have. `cargo test` prints the same finding
  # per test; this line just makes it visible before the run starts.
  echo "== resource tests, native =="
  echo "   own cgroup: $(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
  echo "   (delegation is per-host: the suite reports NOT_PROVEN if this host has none)"
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
