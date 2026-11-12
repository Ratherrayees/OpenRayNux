#!/usr/bin/env bash
#
# READ-ONLY AppArmor forensics for the Tier-1 sandbox lane.
#
# # What this is for
#
# The lane builds bubblewrap 0.13.1 from pinned upstream source and installs it at
# `/usr/local/bin/bwrap`, with `/usr/bin/bwrap` as a SYMLINK to it, because the product
# execs `bwrap` by bare name with an emptied environment and the default search path
# resolves to `/bin:/usr/bin`.
#
# On `ubuntu-26.04` the HOST can sandbox: the `bwrap-userns-restrict` AppArmor profile
# is loaded and grants the `userns` permission to the executable it is attached to. The
# CONTAINER cannot. This script establishes WHY, with observations only.
#
# # What it does NOT do
#
# Nothing here changes the security posture. It does not load or unload a profile, does
# not write a sysctl, does not add a capability, does not use a privileged container, and
# does not pass `apparmor=unconfined`. Every command is a read, a copy, or an attempt to
# execute something that is already installed.
#
# The ONE thing it does that is not a read is a COPY of an already-built binary to a
# second path, to test whether the path or the confinement is the restriction. That copy
# happens inside a throwaway container, is not installed on the host, and is removed with
# the container.
#
# # The two restrictions this is trying to separate
#
# 1. **Path attachment.** AppArmor attaches a profile to a PATH. If the profile is
#    attached to `/usr/bin/bwrap` and the process execs `/usr/local/bin/bwrap` (which is
#    what a symlink resolves to), the profile does not apply, and the `userns` permission
#    it grants is not granted.
# 2. **Confinement transition.** A process confined by `docker-default` does not
#    automatically receive another profile's rules; the transition depends on the target
#    profile's attachment and the child's own confinement.
#
# Both can independently prevent the nested user namespace. This measures them apart.

set -euo pipefail

# The container image the lane uses, by digest. Pinned here for the same reason it is
# pinned in `scripts/run-sandbox-tests.sh`: an unpinned image would make the observation
# unreproducible.
IMAGE="rust:1-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6"

section() { printf '\n===== %s =====\n' "$1"; }

# ---------------------------------------------------------------------------
# HOST: the AppArmor policy as it is loaded on this machine.
# ---------------------------------------------------------------------------
section "HOST: AppArmor state"

echo "apparmor module enabled : $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
echo "unprivileged_userns_clone    : $(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo absent)"

echo
echo "--- loaded profiles (full lines: <name> <mode>) ---"
sudo cat /sys/kernel/security/apparmor/profiles 2>/dev/null \
  | grep -iE 'bwrap|unpriv|docker|^/' \
  | head -40 || echo "(profile list unavailable)"

echo
echo "--- the bwrap profile FILES present on the host ---"
ls -1 /etc/apparmor.d/ 2>/dev/null | grep -iE 'bwrap|unpriv' || echo "(none)"

echo
echo "--- the content of bwrap-userns-restrict (attachment + permissions) ---"
for f in /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/unprivileged_userns; do
  if [ -r "$f" ]; then
    echo "### $f"
    cat "$f"
  else
    echo "### $f : (not readable on this host)"
  fi
done

echo
echo "--- the host's own /proc/self/attr/current (the runner's label) ---"
cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"

# ---------------------------------------------------------------------------
# HOST: the kernel's own AppArmor audit records.
#
# These are the ground truth for a denial: the operation, the profile that refused it,
# and the requesting program. Read-only; nothing is written or cleared.
# ---------------------------------------------------------------------------
section "HOST: kernel AppArmor audit records"

echo "--- dmesg | grep -i apparmor (last 40) ---"
sudo dmesg 2>/dev/null | grep -i apparmor | tail -40 || echo "(dmesg unavailable)"

echo
echo "--- journalctl -k | grep -i apparmor (last 40) ---"
sudo journalctl -k --no-pager 2>/dev/null | grep -i apparmor | tail -40 || echo "(journalctl unavailable)"

# ---------------------------------------------------------------------------
# CONTAINER: the same configuration the lane uses, observed from inside.
#
# The flags below are COPIED from `scripts/run-sandbox-tests.sh` and must stay in step
# with it: `--security-opt seccomp=unconfined` and `--security-opt systempaths=unconfined`,
# no `--privileged`, no `--cap-add`, no `apparmor=unconfined`. A different set would
# measure a different configuration from the one that decides whether a capability runs.
#
# The bubblewrap build is the same pinned 0.13.1 from the same URL with the same SHA-256.
# ---------------------------------------------------------------------------
section "CONTAINER: the same configuration, observed from inside"

docker run --rm \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v "$PWD":/src:ro \
  -w /src \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo "--- the container process AppArmor label ---"
    cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"

    echo
    echo "--- AppArmor state VISIBLE FROM INSIDE the container ---"
    echo "apparmor module enabled : $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
    echo "restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
    echo "loaded profiles visible from inside:"
    sudo cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -20 || echo "(profile list unavailable from inside)"

    echo
    echo "--- build the SAME pinned bubblewrap the lane builds ---"
    BW_VERSION="0.13.1"
    BW_URL="https://deb.debian.org/debian/pool/main/b/bubblewrap/bubblewrap_0.13.1.orig.tar.xz"
    BW_SHA256="0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d"
    apt-get update -qq
    apt-get install -y -qq meson ninja-build pkg-config libcap-dev libselinux1-dev \
                          libpcre2-dev util-linux curl ca-certificates
    BUILD=$(mktemp -d /tmp/bwbuild.XXXXXX)
    curl -fsSL -o "$BUILD/bwrap.tar.xz" "$BW_URL"
    echo "$BW_SHA256  $BUILD/bwrap.tar.xz" | sha256sum -c - || { echo "FATAL: digest mismatch"; exit 1; }
    tar -C "$BUILD" -xf "$BUILD/bwrap.tar.xz"
    cd "$BUILD/bubblewrap-$BW_VERSION"
    meson setup _build -Dman=disabled -Dselinux=enabled -Dtests=false >/dev/null
    ninja -C _build >/dev/null
    meson install -C _build >/dev/null
    BW_BIN="/usr/local/bin/bwrap"
    echo "built and installed: $BW_BIN"

    echo
    echo "=== EXECUTABLE IDENTITY ==="
    echo "real path of /usr/bin/bwrap : $(readlink -f /usr/bin/bwrap 2>/dev/null || echo absent)"
    echo "sha256 of the real binary   : $(sha256sum "$BW_BIN" | cut -d" " -f1)"
    stat -c "  %n  mode=%a  size=%s  inode=%i" "$BW_BIN"
    echo "is /usr/bin/bwrap a symlink? $( [ -L /usr/bin/bwrap ] && echo YES || echo no )"

    echo
    echo "=== ATTEMPT 1: the CURRENT install (real binary at /usr/local/bin, symlink at /usr/bin) ==="
    echo "This is the configuration the lane uses today."
    set +e
    OUT=$(/usr/bin/bwrap --unshare-user --unshare-pid --unshare-uts --die-with-parent \
            --tmpfs /tmp --ro-bind /usr /usr --ro-bind /bin /bin \
            /bin/true 2>&1)
    RC=$?
    set -e
    echo "exit status: $RC"
    echo "output: $OUT"

    echo
    echo "=== ATTEMPT 2: the SAME binary COPIED to a real /usr/bin/bwrap ==="
    echo "This isolates the PATH-ATTACHMENT question: identical bytes, identical container,"
    echo "identical confinement -- only the path the kernel sees differs."
    rm -f /usr/bin/bwrap
    cp "$BW_BIN" /usr/bin/bwrap
    echo "readlink -f /usr/bin/bwrap : $(readlink -f /usr/bin/bwrap)"
    stat -c "  %n  mode=%a  size=%s  inode=%i" /usr/bin/bwrap
    set +e
    OUT=$(/usr/bin/bwrap --unshare-user --unshare-pid --unshare-uts --die-with-parent \
            --tmpfs /tmp --ro-bind /usr /usr --ro-bind /bin /bin \
            /bin/true 2>&1)
    RC=$?
    set -e
    echo "exit status: $RC"
    echo "output: $OUT"

    echo
    echo "=== the container label AFTER both attempts ==="
    cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"
  '

section "DONE"
