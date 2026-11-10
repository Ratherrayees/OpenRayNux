#!/usr/bin/env bash
#
# Tier-1 sandbox tests, in a container configured to reproduce the production sandbox
# posture -- and an honest report when it cannot.
#
# # Why this exists
#
# `linux-gates` runs on a GitHub-hosted Linux runner, on the pinned `ubuntu-24.04` image,
# which cannot create the user namespace `bwrap` needs:
# `kernel.apparmor_restrict_unprivileged_userns` on Ubuntu 24.04+ forbids it. So every
# Tier-1 dispatch there is refused -- correctly, by design (ADR-0035, V-49) -- which means
# that job cannot show that a Tier-1 capability *does* execute under isolation. Something
# has to, or the governed path has no positive evidence in CI at all.
#
# # The measured outcome: on the pinned GitHub-hosted runner, it still cannot
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
# # The restriction is the image's, not hosted CI's (measured 2026-11-08)
#
# A hosted `ubuntu-22.04` image has `kernel.apparmor_restrict_unprivileged_userns` at 0 and
# establishes the production Tier-1 posture on the host itself -- `visibility=true
# tree_lifetime=true`, `tier1_executable: yes`, sandbox identity `uid_map 1001 0 1` with
# `CapEff 0`. The pinned image was measured beside it as the control and reproduced the
# refusal exactly (probe run `42419194419`; V-87). So the lane below is measuring *this
# image*, and running the suites on that host instead is a deliberate change with its own
# reason attached -- not a consequence of the measurement. Until then, there is still no
# positive Tier-1 evidence in CI.
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

# Pinned by **registry manifest digest**, not by tag and not by `latest`, for the reason
# run-resource-tests.sh gives: a test should not change because a tag moved. S-24 makes
# that stricter, because `rust:1-bookworm` is mutable -- it is re-pointed when the Rust
# project publishes a new 1.x tag on that base, and this lane would then build and run
# under a toolchain nobody pinned.
#
# The digest below is the OCI **index** digest for `library/rust:1-bookworm`, read from the
# Docker Hub registry API (`Docker-Content-Digest` on the manifest request) and then
# re-fetched *by digest* to confirm it resolves:
#
#   sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6   index
#   sha256:b36c246742b4d323472588f789601be34eb4af053255e2af53969078ee8dcec7   linux/amd64 manifest
#
# Pinning the **index** rather than the linux/amd64 manifest is deliberate. `sandbox-integration`
# runs on `ubuntu-24.04` (linux/amd64) and would resolve to the second digest, but this
# script is also run by developers, including on arm64 hosts; an amd64-only pin would break
# them at pull time. An index digest is immutable *and* still resolves per platform, which
# is the property wanted. The amd64 digest is recorded above so the resolution this lane
# performs is checkable.
#
# This is a registry manifest digest, not a local `docker images` ID: those are content
# hashes of a locally-unpacked image and mean nothing to a fresh pull.
#
# To move it deliberately, re-read both digests from the registry API and update this line
# -- and note the toolchain change in the same commit, because a new base moves the Rust
# version this lane compiles with.
IMAGE="${ORXNUD_SANDBOX_IMAGE:-rust:1-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6}"

if [ "${1:-}" = "--host" ]; then
  echo "== sandbox tests, host, reporting what was found =="
  echo "   a host that cannot isolate refuses every Tier-1 capability, and the suites"
  echo "   assert that refusal instead of a successful execution."
  ./scripts/preflight.sh
  # The three capability suites are modules inside `orxnud-capability/src/tests/`,
  # not integration binaries. `--test governed_path` fails before a single test runs
  # with "no test target named ..."; these are nextest path filters instead. The same
  # stale spelling was already corrected in `run-sandbox-tests-inner.sh`.
  for suite in \
    "-p orxnud-capability -E test(suites::governed_path)" \
    "-p orxnud-capability -E test(suites::read_text_real)" \
    "-p orxnud-capability -E test(suites::write_text)" \
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
  -v "$PWD/scripts/install-nextest-verified.sh":/install-nextest.sh:ro \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export PATH="/usr/local/cargo/bin:$PATH"

    # Bubblewrap 0.13.1, built from pinned upstream source (V-107 remediation).
    #
    # Why not the distribution package: this base is Debian Bookworm, whose
    # bubblewrap 0.8.0-2+deb12u1 is affected by CVE-2026-87766, and Debian marks the
    # bookworm backport as ignored because the fix is a rewrite -- there is no fixed
    # package to install from the repositories this image configures, and the trixie
    # binary needs GLIBC 2.38 where this base has 2.36. Upstream 0.13.1 replaced
    # pathname resolution with descriptor-based openat2/RESOLVE_IN_ROOT.
    #
    # The three values below travel together and are re-read together: version,
    # source URL, SHA-256. The digest is the one published on the upstream release
    # page, and it was measured from this URL as well. It is a pin on the SOURCE:
    # the build dependencies installed below still resolve from the live Bookworm
    # repositories, so the build is not claimed to be reproducible, only the source
    # is pinned.
    BUBBLEWRAP_VERSION="0.13.1"
    BUBBLEWRAP_URL="https://deb.debian.org/debian/pool/main/b/bubblewrap/bubblewrap_0.13.1.orig.tar.xz"
    BUBBLEWRAP_SHA256="0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d"

    # meson and ninja-build build it, libcap/libselinux/libpcre2 are what the
    # distribution package links, and gcc is already in this image. util-linux is
    # still required -- it provides the setpriv the unprivileged transition below
    # depends on -- and curl with ca-certificates fetch the source over HTTPS with
    # normal certificate validation. No setuid build: upstream no longer supports
    # building one, which is the posture this lane wants regardless.
    apt-get update -qq
    apt-get install -y -qq meson ninja-build pkg-config libcap-dev libselinux1-dev \
                       libpcre2-dev util-linux curl ca-certificates

    BW_BUILD_DIR=$(mktemp -d /tmp/bubblewrap-build.XXXXXX)
    trap "rm -rf -- $BW_BUILD_DIR" EXIT

    # Fetch, failing on HTTP errors and incomplete transfers, then verify the digest
    # BEFORE the archive is extracted or anything from it is executed. The archive is
    # never piped unverified into tar.
    curl -fsSL -o "$BW_BUILD_DIR/bubblewrap.tar.xz" "$BUBBLEWRAP_URL"
    echo "$BUBBLEWRAP_SHA256  $BW_BUILD_DIR/bubblewrap.tar.xz" | sha256sum -c - ||
      { echo "FATAL: bubblewrap source digest mismatch; refusing to build"; exit 1; }

    tar -C "$BW_BUILD_DIR" -xf "$BW_BUILD_DIR/bubblewrap.tar.xz"
    cd "$BW_BUILD_DIR/bubblewrap-$BUBBLEWRAP_VERSION"
    # assume_kernel is deliberately NOT passed. Upstream documents that assuming 5.6
    # compiles out the openat2 fallback, and that assuming 5.12 makes mount_setattr
    # a runtime requirement. Leaving it empty keeps every old-kernel fallback in, so
    # a developer on an older kernel is not silently turned away. The resolved value
    # is asserted below rather than assumed.
    meson setup _build -Dman=disabled -Dselinux=enabled -Dtests=false >/dev/null
    ninja -C _build >/dev/null
    meson install -C _build >/dev/null
    cd /src

    # Assert the resolved build option, not the default we hoped for: a missing or
    # nonempty value means the fallbacks were compiled out and the lane must fail
    # rather than ship a binary that assumes whatever kernel built it.
    BW_BUILDDIR="$BW_BUILD_DIR/bubblewrap-$BUBBLEWRAP_VERSION"
    BW_ASSUME_KERNEL=$(python3 -c "import json;d=json.load(open(\"$BW_BUILDDIR/_build/meson-info/intro-buildoptions.json\"));v=[o[\"value\"] for o in d if o[\"name\"]==\"assume_kernel\"];print(v[0] if v else \"MISSING\")")
    if [ "$BW_ASSUME_KERNEL" != "" ]; then
      echo "FATAL: meson assume_kernel resolved to \"$BW_ASSUME_KERNEL\"; leaving it empty is"
      echo "       what keeps the old-kernel openat2 and mount_setattr fallbacks compiled in."
      exit 1
    fi

    # Post-install assertions, absolute paths, failing the lane on any of them.
    BW_BIN="/usr/local/bin/bwrap"
    if [ ! -f "$BW_BIN" ]; then
      echo "FATAL: $BW_BIN does not exist"; exit 1
    fi
    if [ -L "$BW_BIN" ]; then
      echo "FATAL: $BW_BIN is a symlink; the installed binary must be a regular file"; exit 1
    fi
    if [ ! -x "$BW_BIN" ]; then
      echo "FATAL: $BW_BIN is not executable"; exit 1
    fi
    BW_MODE=$(stat -c %a "$BW_BIN")
    if [ "$BW_MODE" != "755" ]; then
      echo "FATAL: $BW_BIN mode is $BW_MODE, expected 755"; exit 1
    fi
    BW_REPORTED=$("$BW_BIN" --version)
    if [ "$BW_REPORTED" != "bubblewrap $BUBBLEWRAP_VERSION" ]; then
      echo "FATAL: $BW_BIN reports \"$BW_REPORTED\", expected \"bubblewrap $BUBBLEWRAP_VERSION\""; exit 1
    fi
    # The suites spawn bwrap by PATH lookup (BWRAP = "bwrap" in linux.rs), so the
    # resolution has to land on the binary just installed.
    if [ "$(command -v bwrap)" != "$BW_BIN" ]; then
      echo "FATAL: bwrap resolves to $(command -v bwrap), expected $BW_BIN"; exit 1
    fi

    # Why the /usr/local install alone is not enough, and what closes the gap.
    #
    # `spawn_supervisor` runs `Command::new(BWRAP)` with `env_clear()` (linux.rs) so a
    # parent secret cannot reach the child. With an empty environment the exec lookup no
    # longer uses the caller PATH: it falls back to glibc default path, measured on this
    # image as `/bin:/usr/bin`, where `/usr/local/bin` does not appear.
    #
    # So installing only to /usr/local leaves every sandboxed execution failing with
    # ENOENT, while the preflight -- which does not clear the environment -- still finds
    # bwrap and reports that a Tier-1 capability can execute. That asymmetry is how this
    # was found: the lane asserted the binary several ways and still ran nothing, and a
    # shell PATH check of any thoroughness cannot see it. The emptied-environment
    # assertion below performs the lookup the runner actually performs.
    #
    # The fix is to expose the same binary at the default path as a symlink, not a second
    # copy, so there is one binary and two names. The checks that follow make that safe:
    # nothing package-owned may already hold the path, no unexpected object may be
    # replaced, and the link is created without force.
    #
    # Package-level check against the installed-package status database, which is a
    # different database from the path-ownership search below.
    #
    # `dpkg-query -S` searches the per-package file lists under /var/lib/dpkg/info, so a
    # missing or damaged <package>.list hides the files of that package from it while the
    # package remains installed. dpkg says so only in a warning on stderr, which this
    # guard discards, so a negative answer from the path search is not trustworthy on its
    # own. /var/lib/dpkg/status is a separate file, unaffected by that loss: deleting
    # bubblewrap.list does not remove the package status, and this check still sees the
    # installation. Deleting the file-list record and the status record at once is a
    # different kind of damage, and the sentinel below is what catches it.
    #
    # The decision is on the machine-readable status word, never on English output:
    #
    #   rc=0 and the status word is not-installed -> the package is unequivocally absent
    #   rc=0 and any other status word            -> installed, residual (config-files) or
    #                                               transitional (unpacked, half-installed,
    #                                               half-configured): FATAL
    #   rc=1                                      -> no record of the package; permitted
    #                                               only because the sentinel above has
    #                                               already shown the database readable
    #   rc=2 or any unexpected result             -> a fatal or unrecoverable error; it is
    #                                               never read as evidence of absence: FATAL
    #
    # Only the first outcome is acceptable, and ambiguity never reads as absence. The
    # query is also first shown to work against a package that is certainly installed --
    # the same sentinel pattern the path check uses -- because if that control cannot be
    # found the status database is not readable and absence cannot be established, which
    # is not evidence of absence.
    if ! dpkg-query -W -f="\${Status}\n" dpkg >/dev/null 2>&1; then
      echo "FATAL: cannot read the installed-package status database -- dpkg-query found no"
      echo "       record for the dpkg package itself -- so the absence of the bubblewrap"
      echo "       package cannot be established"
      exit 1
    fi

    set +e
    BW_PKG_STATUS=$(dpkg-query -W -f="\${db:Status-Status}\n" bubblewrap 2>/dev/null)
    BW_PKG_RC=$?
    set -e
    case "$BW_PKG_RC" in
      0)
        if [ "$BW_PKG_STATUS" != "not-installed" ]; then
          echo "FATAL: the bubblewrap package is present in the installed-package status"
          echo "       database (status: $BW_PKG_STATUS); the distribution bubblewrap package"
          echo "       must not be installed, and a local symlink must not shadow it"
          exit 1
        fi
        ;;
      1)
        # No record of the package at all. Permitted only because the sentinel above has
        # already shown the status database readable, so this is not exit 1 relied on
        # alone.
        ;;
      *)
        echo "FATAL: the bubblewrap status query exited $BW_PKG_RC; 2 is a fatal or"
        echo "       unrecoverable error, and an unexpected result is not evidence that the"
        echo "       package is absent"
        exit 1
        ;;
    esac

    # Fail closed on path ownership.
    #
    # `dpkg-query -S` cannot be trusted on its exit code alone: it exits 1 both when no
    # package owns a path and when it cannot read a usable database, and it prints the
    # same "no path found matching pattern" wording in both cases -- so exit status and
    # message text are both incapable of telling "unowned" from "unable to tell". The
    # probe is therefore first shown to work, by finding a path that is certainly owned
    # in any Debian container: the dpkg-query binary being executed right now. If that
    # control does not resolve to a package, ownership could not be established at all,
    # and an inability to establish ownership is not evidence of non-ownership -- so the
    # lane stops here rather than writing to a path it cannot reason about.
    if ! dpkg-query -S /usr/bin/dpkg-query >/dev/null 2>&1; then
      echo "FATAL: cannot establish package ownership -- dpkg-query found no owner for its"
      echo "       own /usr/bin/dpkg-query -- so /usr/bin/bwrap ownership is unknown"
      exit 1
    fi
    if dpkg-query -S /usr/bin/bwrap >/dev/null 2>&1; then
      echo "FATAL: /usr/bin/bwrap is owned by a package; the distribution bubblewrap package"
      echo "       must not be installed, and a local symlink must not shadow it"
      exit 1
    fi

    # Reject anything already at the default path, and accept exactly one pre-existing
    # state: an unowned symlink pointing at the binary just installed. A foreign
    # symlink, a dangling symlink, a regular file, a directory or any other object is
    # refused rather than replaced -- which is what keeps a stale build or a
    # package-managed link from silently taking the name.
    #
    # `[ -e ]` alone is not enough: it is false for a dangling symlink, so the symlink
    # test is made on its own and the object is classified for the failure message.
    if [ -e /usr/bin/bwrap ] || [ -L /usr/bin/bwrap ]; then
      if [ -L /usr/bin/bwrap ] && [ "$(readlink /usr/bin/bwrap)" = "$BW_BIN" ]; then
        echo "   default-path link: /usr/bin/bwrap -> $BW_BIN (already present)"
      else
        if [ -L /usr/bin/bwrap ]; then
          BW_WHAT="a symlink to $(readlink /usr/bin/bwrap)"
        else
          BW_WHAT="an existing non-symlink object"
        fi
        echo "FATAL: /usr/bin/bwrap already exists as $BW_WHAT and will not be replaced"
        exit 1
      fi
    fi

    # Create the link WITHOUT force, now that absence -- or an already-correct link --
    # has been established. If anything appears at that path between the check above and
    # this call, `ln -s` fails and the lane stops, instead of overwriting it.
    if [ ! -e /usr/bin/bwrap ] && [ ! -L /usr/bin/bwrap ]; then
      ln -s "$BW_BIN" /usr/bin/bwrap
    fi
    if [ "$(readlink /usr/bin/bwrap)" != "$BW_BIN" ]; then
      echo "FATAL: /usr/bin/bwrap does not resolve to $BW_BIN"; exit 1
    fi

    # The decisive assertion: the lookup a spawn with an emptied environment performs.
    # `env -i` clears the environment, so the name is resolved exactly as the sandbox
    # runner resolves it. If this reports a different binary, or nothing at all, the lane
    # fails here rather than producing green suites that ran no sandboxed subprocess.
    BW_EMPTY_ENV=$(env -i python3 -c "import os;os.execvp(\"bwrap\",[\"bwrap\",\"--version\"])" 2>/dev/null)
    if [ "$BW_EMPTY_ENV" != "bubblewrap $BUBBLEWRAP_VERSION" ]; then
      echo "FATAL: a process with an emptied environment resolves bwrap as [$BW_EMPTY_ENV];"
      echo "       the sandbox runner spawns bwrap that way, so execution would fail"; exit 1
    fi

    echo "== bubblewrap: built from pinned upstream source, not the distribution package =="
    echo "   source:         $BUBBLEWRAP_URL"
    echo "   sha256:         $BUBBLEWRAP_SHA256 (verified before extraction)"
    echo "   version:        $BW_REPORTED"
    echo "   installed:      $BW_BIN (regular file, mode $BW_MODE)"
    echo "   PATH resolution: $(command -v bwrap)"
    echo "   default-path link: /usr/bin/bwrap -> $(readlink /usr/bin/bwrap)"
    echo "   emptied-environment lookup: $BW_EMPTY_ENV"
    echo "   assume_kernel:  (empty -- old-kernel fallbacks compiled in)"
    echo

    useradd --create-home --uid 1000 orxnud
    chown -R orxnud /usr/local/cargo/registry
    chmod -R a+rX /usr/local/cargo

    # cargo-nextest is not in the image and the suites are selected with its filters. The
    # prebuilt binary is a download rather than a `cargo install`, which would add minutes
    # of compilation to every uncached run.
    #
    # S-24: it is a *pinned, checksum-verified* download, and it is installed and executed
    # as uid 1000 into a directory that uid owns. It used to be an unversioned
    # `curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C /usr/local/cargo/bin`,
    # executed as root into a system path on every push -- see
    # `scripts/install-nextest-verified.sh` for what was wrong with that and what replaced
    # each part of it.
    #
    # This runs BEFORE `cargo test --workspace --no-run` below, and `set -euo pipefail` is
    # already in force, so a checksum mismatch fails the lane before any build step starts.
    install -d -m 0755 -o 1000 -g 1000 /home/orxnud/.local/bin /home/orxnud/.local/tmp
    setpriv --reuid=1000 --regid=1000 --clear-groups \
            --inh-caps=-all --bounding-set=-all -- \
      env HOME=/home/orxnud TMPDIR=/home/orxnud/.local/tmp \
          PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      bash /install-nextest.sh /home/orxnud/.local/bin

    export PATH="/home/orxnud/.local/bin:$PATH"

    # Build as root so the caches stay warm, and *run* as the unprivileged user. The
    # security-relevant process is the one that spawns bwrap, and that must be
    # unprivileged.
    #
    # The chown AFTER the build is load-bearing, and exists because CI found it: a root
    # build recreates root-owned files under /target, and the unprivileged cargo then cannot
    # open /target/debug/.cargo-build-lock. Chowning before the build is not enough.
    cargo test --workspace --no-run >/dev/null
    chown -R orxnud /target

    # HOME and the XDG directories are set for the unprivileged run. This is not
    # tidiness -- it is what makes the lane run at all.
    #
    # `setpriv` changes the uid but does not touch the environment, so the child
    # inherited HOME=/root from the root shell that started it. cargo-nextest then
    # looked for its user config under /root/.config and died:
    #
    #     error: failed to read user config at /root/.config/nextest/config.toml
    #     Caused by: Permission denied (os error 13)
    #
    # which aborted the lane before a single Tier-1 test ran. Found by running this lane
    # end to end for the first time; the defect predates S-17 and S-24.
    #
    # No apostrophes in this comment: the whole bootstrap is a single-quoted string
    # passed to `bash -lc`, so one would terminate it. That is not a style preference --
    # it is a syntax error, and the script would fail to run at all.
    #
    # The variables are set on the setpriv line rather than exported globally, so the
    # root build above still sees the root environment.
    # The suites resolve bwrap by PATH lookup, so the binary that actually runs is
    # the one the unprivileged test process resolves -- and that process is started
    # by the exec below, whose environment is not the root shell environment. So
    # assert the resolution inside that exact transition: same uid, same capability
    # drops, same environment, only the program differs. A PATH that would reach
    # inner.sh differently fails the lane here instead of silently running a
    # different binary. The check runs as uid 1000 with no capabilities, which is
    # also the least privileged state from which it could be asked.
    setpriv --reuid=1000 --regid=1000 --clear-groups \
            --inh-caps=-all --bounding-set=-all -- \
      env HOME=/home/orxnud \
          XDG_CONFIG_HOME=/home/orxnud/.config \
          XDG_CACHE_HOME=/home/orxnud/.cache \
          XDG_DATA_HOME=/home/orxnud/.local/share \
      /bin/bash -c "
        resolved=\$(command -v bwrap)
        if [ \"\$resolved\" != \"$BW_BIN\" ]; then
          echo \"FATAL: the unprivileged test environment resolves bwrap to \$resolved,\"
          echo \"       expected $BW_BIN\"
          exit 1
        fi
        reported=\"\$($BW_BIN --version)\"
        if [ \"\$reported\" != \"bubblewrap $BUBBLEWRAP_VERSION\" ]; then
          echo \"FATAL: the unprivileged test environment sees \$reported,\"
          echo \"       expected bubblewrap $BUBBLEWRAP_VERSION\"
          exit 1
        fi
        echo \"   as uid 1000, no capabilities: bwrap resolves to \$resolved (\$reported)\"
      "

    exec setpriv --reuid=1000 --regid=1000 --clear-groups \
                 --inh-caps=-all --bounding-set=-all -- \
      env HOME=/home/orxnud \
          XDG_CONFIG_HOME=/home/orxnud/.config \
          XDG_CACHE_HOME=/home/orxnud/.cache \
          XDG_DATA_HOME=/home/orxnud/.local/share \
      /bin/bash /inner.sh
  '
