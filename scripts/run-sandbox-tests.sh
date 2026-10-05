#!/usr/bin/env bash
#
# Tier-1 sandbox tests, in a container that reproduces the *production* sandbox
# configuration.
#
# # Why a container, and why this one
#
# A GitHub-hosted Linux runner ships `bwrap` and cannot use it. Ubuntu 24.04+ sets
# `kernel.apparmor_restrict_unprivileged_userns`, and without a per-binary AppArmor grant
# `bwrap --unshare-pid` fails, so `BwrapRunner::probe()` reports no guarantees and every
# Tier-1 dispatch is refused. That refusal is the product behaving correctly (ADR-0035,
# V-49) -- but it means the runner cannot produce evidence that a Tier-1 capability *does*
# execute under isolation.
#
# The first container idea does not fix that, and this script is shaped by having measured
# why. Measured, on this repository, with `bwrap --version` present in every case:
#
#   | container configuration                        | probe    |
#   |-----------------------------------------------|----------|
#   | default                                        | FAIL     |
#   | `--security-opt seccomp=unconfined`            | FAIL     |
#   | `--cap-add=SYS_ADMIN`                          | FAIL (pivot_root) |
#   | `--privileged`                                 | PASS     |
#   | `--cap-add=SYS_ADMIN --security-opt seccomp=unconfined` | PASS |
#
# Only `--privileged` and `CAP_SYS_ADMIN` pass, and **both are disqualifying**. Inside such
# a container `bwrap` does not create a user namespace at all: it runs with the caller's
# pre-existing privilege over the container's own mount namespace. Measured signatures:
#
#   | where                                     | uid_map inside sandbox | CapEff inside |
#   |-------------------------------------------|------------------------|---------------|
#   | production (unprivileged host)             | `1000 0 1`             | `0`           |
#   | `--cap-add=SYS_ADMIN` container            | `0 0 4294967295`       | `a82425fb`    |
#
# The second row is the full identity map, which is the signature of *no* nested user
# namespace. A sandbox measured that way never exercises the unprivileged-userns path every
# real user depends on, so a green run there would be evidence about a configuration
# OpenRayNux will never ship. That is the reason this script does not use `--privileged`
# and does not add capabilities, rather than a stylistic preference.
#
# # What this container does instead
#
# Two runtime-only relaxations, neither of which grants a capability:
#
# * `--security-opt seccomp=unconfined`. Docker's default seccomp profile returns EPERM for
#   `unshare(CLONE_NEWUSER)`, which is measured above: with seccomp on, even
#   `unshare -U` fails. This removes a syscall filter. It grants nothing.
# * `--security-opt systempaths=unconfined`. Docker bind-mounts `/dev/null` over
#   `/proc/kcore`, `/proc/sys` and friends. A procfs with masked paths is not "fully
#   visible", and the kernel refuses a fresh procfs mount inside a nested user namespace --
#   measured, as `bwrap: Can't mount proc on /proc: Operation not permitted`. This stops
#   the masking. It grants nothing.
#
# The test process then runs as an unprivileged non-root user with every capability
# dropped, via `setpriv`. So `bwrap` has no choice but to nest a user namespace, exactly as
# on a user's desktop, and the preflight below prints the signature to prove it did.
#
# # The lane fails rather than degrades
#
# `scripts/preflight.sh --require` runs first and exits non-zero if a Tier-1 capability
# cannot be sandboxed here, or if the sandbox identity is not the nested/production shape.
# So if this container ever stops reproducing production, the lane fails with that stated
# -- it does not quietly run a reduced suite and pass. That is the whole reason the
# preflight has a `--require` mode.
#
# # What it does not prove
#
# Nothing about the host that launched it. The runner's own inability is real and is
# reported by the preflight in the host lane; this container is a second, explicitly
# labelled environment, not a repair of the first.
#
# # Usage
#
#   scripts/run-sandbox-tests.sh              # the container
#   scripts/run-sandbox-tests.sh --host       # the host, reporting what it found

set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned by digest-free tag, matching run-resource-tests.sh's reasoning: a test should not
# change because a tag moved.
IMAGE="${ORXNUD_SANDBOX_IMAGE:-rust:1-bookworm}"

# The suites whose subject is Tier-1 sandboxed execution. Listed here rather than left to
# `cargo nextest run --workspace` so the lane's scope is visible in one place, and so
# adding a sandbox-dependent suite is a deliberate edit to this file.
# Namespace/visibility evidence only -- the part that depends on an unprivileged user
# namespace, which is what this container reproduces.
#
# `orxnud-platform-sandbox`'s `enforcement` and `resources` binaries are deliberately NOT
# here. They assert cgroup v2 ceilings bite, which needs *delegation*: writing a controller
# file requires CAP_SYS_ADMIN over the hierarchy, so it requires a privileged container --
# and that is a different question from "can this process isolate a subprocess". Granting
# it here would mean granting CAP_SYS_ADMIN, which is precisely the configuration ADR-0046
# rejects as evidence about the sandbox. Those suites have their own home and it is the
# right one: `scripts/run-resource-tests.sh`, which runs them in a `--privileged
# --cgroupns=host` container and says why that is not a sandbox-privilege question.
SUITES=(
  "-p orxnud-capability --test governed_path"
  "-p orxnud-capability --test read_text_real"
  "-p orxnud-capability --test write_text"
  "-p orxnud-platform-sandbox --test isolation"
  "-p orxnud-platform-sandbox --lib"
  "-p orxnuctl --test cli_e2e"
)

if [ "${1:-}" = "--host" ]; then
  echo "== sandbox tests, host, reporting what was found =="
  echo "   a host that cannot isolate refuses every Tier-1 capability, and the suites"
  echo "   below assert that refusal instead of a successful execution."
  cargo run -q -p orxnud-platform-sandbox --example preflight
  for suite in "${SUITES[@]}"; do
    # shellcheck disable=SC2086 # the suite is intentionally several words
    cargo nextest run $suite --no-fail-fast
  done
  exit $?
fi

echo "== sandbox tests, production-configuration container =="
echo "   image:  $IMAGE"
echo "   grants: no --privileged, no --cap-add; an unprivileged uid with all capabilities dropped"
echo "   proves: a Tier-1 capability executes under real isolation, in the same"
echo "           configuration an unprivileged user runs it in."

docker run --rm \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v "$PWD":/src:ro \
  -v orxnud-sandbox-registry:/usr/local/cargo/registry \
  -v orxnud-sandbox-target:/target \
  -w /src \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_HOME=/usr/local/cargo \
  -v "$PWD/scripts/preflight.sh":/preflight.sh:ro \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export PATH="/usr/local/cargo/bin:$PATH"

    apt-get update -qq
    apt-get install -y -qq bubblewrap util-linux curl ca-certificates

    # `cargo-nextest` is not in the image, and the suites are selected with its filters.
    # The prebuilt binary is a download rather than a `cargo install`, which would add
    # minutes of compilation to every uncached run.
    if ! cargo nextest --version >/dev/null 2>&1; then
      curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C /usr/local/cargo/bin
    fi
    cargo nextest --version

    # A real unprivileged user, and a build cache it owns, so `setpriv` can drop every
    # capability and still write to /target.
    useradd --create-home --uid 1000 orxnud
    chown -R orxnud /usr/local/cargo/registry
    chmod -R a+rX /usr/local/cargo

    # Build as root, so the caches stay writable and warm across runs, and *run* as the
    # unprivileged user. The split is deliberate: the security-relevant process is the
    # one that spawns bwrap, and that must be unprivileged.
    #
    # The chown AFTER the build is load-bearing, and it exists because CI found it: a root
    # build creates root-owned files under /target, and the unprivileged `cargo run` then
    # cannot open `/target/debug/.cargo-build-lock`. Chowning before the build is not
    # enough, because the build is what makes the files root-owned again.
    # `cargo test --no-run` rather than `cargo nextest build`: nextest 0.9.146 has no
    # `build` subcommand, and this only needs the test binaries compiled.
    cargo test --workspace --no-run >/dev/null
    chown -R orxnud /target

    exec setpriv --reuid=1000 --regid=1000 --clear-groups \
                 --inh-caps=-all --bounding-set=-all -- \
      /bin/bash -c "
        set -euo pipefail
        export PATH=/usr/local/cargo/bin:\$PATH

        echo
        echo \"-- preflight (fails the lane if this is not the production configuration) --\"
        cargo run -q -p orxnud-platform-sandbox --example preflight -- --require

        echo
        echo \"-- Tier-1 suites, as uid \$(id -u) with CapEff \$(grep CapEff /proc/self/status | cut -f2) --\"
        $(for s in "${SUITES[*]}"; do echo "cargo nextest run $s --no-fail-fast"; echo; done)
      "
  '
