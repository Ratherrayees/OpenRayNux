#!/usr/bin/env bash
#
# Tier-1 sandbox tests, in a container configured to reproduce the production sandbox
# posture -- and an honest report when it cannot.
#
# # Why this exists
#
# `linux-gates` runs on a GitHub-hosted Linux runner, which ships `bwrap` and cannot use
# it: `kernel.apparmor_restrict_unprivileged_userns` on Ubuntu 24.04+ forbids the
# unprivileged user namespace `bwrap` needs. So every Tier-1 dispatch there is refused --
# correctly, by design (ADR-0035, V-49) -- which means that job cannot show that a Tier-1
# capability *does* execute under isolation. Something has to, or the governed path has no
# positive evidence in CI at all.
#
# # The measured outcome: on a GitHub-hosted runner, it still cannot
#
# Inside this container, on `ubuntu-latest`:
#
#     uid / gid:   1000 / 1000
#     CapEff:      0000000000000000
#     guarantees: visibility=false tree_lifetime=false resources=false
#     tier1_executable: no
#
# The unprivileged uid and the dropped capabilities both took effect, and the namespace
# probe still failed. The AppArmor restriction applies to processes inside the container
# too, so neither `seccomp=unconfined` nor `systempaths=unconfined` is enough. The
# measurements behind each of those two, and the configurations that were rejected, are in
# the register as V-86.
#
# This was not predictable from a developer machine. On a host with no AppArmor loaded, the
# same container *does* reproduce production -- verified, with the nested signature
# `uid_map 1000 0 1` and `CapEff 0`, against the full identity map `0 0 4294967295` that a
# `--cap-add=SYS_ADMIN` container produces. So a local pass would have been a false
# assurance, and measuring on the runner is the only reason that is known.
#
# # What this script will not do
#
# It will not disable AppArmor's userns restriction, and it will not load a per-binary
# AppArmor profile for `bwrap` on the runner. Either is a host security-policy change made
# so a test can pass -- the trade `scripts/run-resource-tests.sh` already declines, in
# more words, about a desktop session's cgroup delegation.
#
# So when the container cannot isolate, the inner script says so in capitals, produces no
# positive evidence, and exits successfully. It does not skip quietly and it does not
# weaken a contract to manufacture a green run. **A green job here means "the environment
# was measured and reported", not "the sandbox was proven."**
#
# # Where the positive evidence actually comes from
#
# A host that can create an unprivileged user namespace:
#
#   * a developer machine   -- scripts/run-sandbox-tests.sh --host
#   * a container on such a host -- scripts/run-sandbox-tests.sh
#   * cgroup enforcement -- scripts/run-resource-tests.sh, which needs delegation and
#     therefore a different container again
#
# Windows isolation remains NOT_PROVEN (ADR-0035, V-29). Nothing here changes that.

set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned by tag rather than `latest`, for the reason run-resource-tests.sh gives: a test
# should not change because a tag moved.
IMAGE="${ORXNUD_SANDBOX_IMAGE:-rust:1-bookworm}"

if [ "${1:-}" = "--host" ]; then
  echo "== sandbox tests, host, reporting what was found =="
  echo "   a host that cannot isolate refuses every Tier-1 capability, and the suites"
  echo "   assert that refusal instead of a successful execution."
  ./scripts/preflight.sh
  for suite in \
    "-p orxnud-capability --test governed_path" \
    "-p orxnud-capability --test read_text_real" \
    "-p orxnud-capability --test write_text" \
    "-p orxnud-platform-sandbox --test isolation" \
    "-p orxnuctl --test cli_e2e" \
    "-p orxnud-daemon --test continuation" \
    "-p orxnud-daemon --test disclosure" \
    "-p orxnud-daemon --test expiry"; do
    # shellcheck disable=SC2086 # the suite is intentionally several words
    cargo nextest run $suite --no-fail-fast
  done
  exit $?
fi

echo "== sandbox tests, container configured for the production posture =="
echo "   image:  $IMAGE"
echo "   grants: no --privileged, no --cap-add; an unprivileged uid with all capabilities dropped"
echo "   expects: a Tier-1 capability to execute under real isolation."
echo "   if it cannot, the lane reports that and produces no positive evidence -- read the output."

# Two runtime-only relaxations, neither of which grants a capability:
#
#   * seccomp=unconfined         Docker's default profile returns EPERM for
#                                unshare(CLONE_NEWUSER); with it on, even `unshare -U` fails.
#   * systempaths=unconfined     Docker bind-mounts over /proc/kcore and /proc/sys, so procfs
#                                is not "fully visible" and the kernel refuses a nested
#                                procfs mount.
#
# `--security-opt apparmor=unconfined` was tried and does not help: the restriction is
# `kernel.apparmor_restrict_unprivileged_userns`, not a profile on bwrap.
docker run --rm \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v "$PWD":/src:ro \
  -v orxnud-sandbox-registry:/usr/local/cargo/registry \
  -v orxnud-sandbox-target:/target \
  -w /src \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_HOME=/usr/local/cargo \
  -v "$PWD/scripts/run-sandbox-tests-inner.sh":/inner.sh:ro \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export PATH="/usr/local/cargo/bin:$PATH"

    apt-get update -qq
    apt-get install -y -qq bubblewrap util-linux curl ca-certificates

    # cargo-nextest is not in the image and the suites are selected with its filters. The
    # prebuilt binary is a download rather than a `cargo install`, which would add minutes
    # of compilation to every uncached run.
    if ! cargo nextest --version >/dev/null 2>&1; then
      curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C /usr/local/cargo/bin
    fi

    useradd --create-home --uid 1000 orxnud
    chown -R orxnud /usr/local/cargo/registry
    chmod -R a+rX /usr/local/cargo

    # Build as root so the caches stay warm, and *run* as the unprivileged user. The
    # security-relevant process is the one that spawns bwrap, and that must be
    # unprivileged.
    #
    # The chown AFTER the build is load-bearing, and exists because CI found it: a root
    # build recreates root-owned files under /target, and the unprivileged cargo then cannot
    # open /target/debug/.cargo-build-lock. Chowning before the build is not enough.
    cargo test --workspace --no-run >/dev/null
    chown -R orxnud /target

    exec setpriv --reuid=1000 --regid=1000 --clear-groups \
                 --inh-caps=-all --bounding-set=-all -- \
      /bin/bash /inner.sh
  '
