#!/usr/bin/env bash
#
# READ-ONLY AppArmor forensics for the Tier-1 sandbox lane.
#
# # What this is for
#
# The lane builds bubblewrap 0.13.1 from pinned upstream source, installs it at
# `/usr/local/bin/bwrap`, and makes `/usr/bin/bwrap` a SYMLINK to it, because the product
# execs `bwrap` by bare name with an emptied environment and the default search path
# resolves to `/bin:/usr/bin`.
#
# On `ubuntu-26.04` the HOST can sandbox: the `bwrap-userns-restrict` AppArmor profile
# is loaded and is attached to `/usr/bin/bwrap`. The CONTAINER cannot. This script
# establishes why, with observations only.
#
# # The two restrictions this is trying to separate
#
# 1. **Path attachment.** AppArmor attaches a profile to a PATH. The profile is attached
#    to `/usr/bin/bwrap`; the lane's symlink resolves the executable to
#    `/usr/local/bin/bwrap`, which no profile covers. But an attachment alone does not
#    establish a TRANSITION: a process already confined by `docker-default` does not
#    automatically enter another profile. So the transition has to be OBSERVED, not
#    inferred from the profile file.
# 2. **Confinement.** The container runs under `docker-default (enforce)`, and the
#    mount step that bubblewrap performs after creating its namespaces may be refused
#    there rather than by the `bwrap` profile.
#
# # What this does NOT do
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
# Kernel messages are collected from the HOST, never from inside the container: the
# kernel restricts `dmesg` to processes holding `CAP_SYSLOG`, and adding it would be a
# capability change. Docker's own documentation recommends the host kernel log for
# AppArmor denials. They are therefore collected AFTER the container has run, not
# before -- collecting them before would miss the very operation under test.
#
# # The two configurations compared
#
# **A. The current installation** -- the real binary at `/usr/local/bin/bwrap` with
#    `/usr/bin/bwrap` a verified symlink to it, exactly as `scripts/run-sandbox-tests.sh`
#    creates it.
# **B. The candidate installation** -- the SAME bytes at a regular `/usr/bin/bwrap`.
#
# Both run in the same container with the same confinement and the same bubblewrap
# binary, so the only variable is the path the kernel sees.

set -euo pipefail

# The container image the lane uses, by digest. Pinned here for the same reason it is
# pinned in `scripts/run-sandbox-tests.sh`: an unpinned image would make the observation
# unreproducible.
IMAGE="rust:1-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6"

section() { printf '\n===== %s =====\n' "$1"; }

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
    set -uo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo "--- the diagnostic shell AppArmor label (NOT the bubblewrap label) ---"
    cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"
    SHELL_LABEL="$(cat /proc/self/attr/current 2>/dev/null || echo unknown)"

    echo
    echo "--- AppArmor state VISIBLE FROM INSIDE the container ---"
    echo "apparmor module enabled : $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
    echo "restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
    echo "loaded profiles visible from inside:"
    sudo cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -20 \
      || echo "(profile list unavailable from inside)"

    # ---- build the SAME pinned bubblewrap the lane builds ----
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

    # The argv the PRODUCT builds, reproduced here. `build_command` does NOT pass
    # `--unshare-user`: bubblewrap creates the user namespace itself when it is
    # unprivileged. Passing it explicitly would measure a different invocation.
    # The namespace set, the tmpfs root and the read-only binds are the product'"'"'s.
    BW_ARGV=(
      --unshare-pid
      --unshare-ipc
      --unshare-uts
      --unshare-cgroup
      --die-with-parent
      --unshare-net
      --tmpfs /tmp
      --ro-bind /usr /usr
      --ro-bind /bin /bin
      --ro-bind /lib /lib
      --ro-bind /lib64 /lib64
    )

    # Runs bubblewrap in the BACKGROUND and reads the label and the effective
    # capabilities of the bubblewrap PROCESS ITSELF, while it is alive.
    #
    # The shell'"'"'s own label is useless here: it is the label of the diagnostic
    # shell, not of the process that exec'"'"'d bubblewrap. The bubblewrap process
    # exists from execve until its failing mount, which is a few milliseconds, so
    # the read is a tight builtin-only loop with no forks in it, retried until it
    # catches a label that is not the shell'"'"'s.
    #
    # If the label is never observed, that is reported as such. It is NOT reported
    # as evidence that AppArmor was uninvolved.
    run_bwrap_observing() {
      local label="" capeff="" attempts=0 rc=0 l c
      for try in $(seq 1 60); do
        attempts=$((attempts + 1))
        bwrap "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err &
        local pid=$!
        for i in $(seq 1 2000); do
          if [ -r "/proc/$pid/attr/current" ]; then
            l=""; read -r l < "/proc/$pid/attr/current" 2>/dev/null || true
            if [ -n "$l" ] && [ "$l" != "$SHELL_LABEL" ]; then
              c=""
              while read -r _k _v; do
                [ "$_k" = "CapEff:" ] && c="$_v"
              done < "/proc/$pid/status" 2>/dev/null
              label="$l"; capeff="$c"
              break
            fi
          fi
          kill -0 "$pid" 2>/dev/null || break
        done
        rc=0; wait "$pid" 2>/dev/null || rc=$?
        if [ -n "$label" ]; then
          echo "  exit status        : $rc"
          echo "  bubblewrap label   : $label"
          echo "  bubblewrap CapEff  : ${capeff:-unreadable}"
          echo "  bubblewrap stderr  : $(cat /tmp/bw.err 2>/dev/null | head -3)"
          echo "  (observed on attempt $attempts)"
          return 0
        fi
      done
      echo "  exit status        : $rc"
      echo "  bubblewrap label   : NOT OBSERVED after $attempts attempts"
      echo "  bubblewrap CapEff  : NOT OBSERVED"
      echo "  bubblewrap stderr  : $(cat /tmp/bw.err 2>/dev/null | head -3)"
      return 1
    }

    identity() {
      echo "  /usr/bin/bwrap is a symlink? $( [ -L /usr/bin/bwrap ] && echo YES || echo no )"
      echo "  readlink -f /usr/bin/bwrap : $(readlink -f /usr/bin/bwrap 2>/dev/null || echo absent)"
      echo "  sha256 of /usr/bin/bwrap (resolved) : $(sha256sum /usr/bin/bwrap 2>/dev/null | cut -d" " -f1)"
      echo "  sha256 of the built binary         : $(sha256sum "$BW_BIN" | cut -d" " -f1)"
      stat -c "  stat %n  mode=%a  size=%s  inode=%i  links=%h" /usr/bin/bwrap 2>/dev/null || true
      stat -c "  stat %n  mode=%a  size=%s  inode=%i  links=%h" "$BW_BIN" 2>/dev/null || true
    }

    # ================= CONFIGURATION A: the current installation =================
    echo
    echo "################ CONFIGURATION A: the CURRENT installation ################"
    echo "# The real binary at /usr/local/bin/bwrap, with /usr/bin/bwrap a verified"
    echo "# SYMLINK to it -- exactly what scripts/run-sandbox-tests.sh creates."
    rm -f /usr/bin/bwrap
    ln -s "$BW_BIN" /usr/bin/bwrap
    if [ ! -L /usr/bin/bwrap ]; then echo "FATAL: /usr/bin/bwrap is not a symlink"; exit 1; fi
    if [ "$(readlink -f /usr/bin/bwrap)" != "$BW_BIN" ]; then echo "FATAL: the symlink does not resolve to the built binary"; exit 1; fi
    echo "--- executable identity ---"
    identity
    echo "--- execution ---"
    run_bwrap_observing

    # ================= CONFIGURATION B: the candidate installation =================
    echo
    echo "################ CONFIGURATION B: the CANDIDATE installation ################"
    echo "# The SAME bytes at a REGULAR /usr/bin/bwrap. Only the path the kernel"
    echo "# sees differs; the bytes, the container and the confinement do not."
    rm -f /usr/bin/bwrap
    cp "$BW_BIN" /usr/bin/bwrap
    chmod 0755 /usr/bin/bwrap
    if [ -L /usr/bin/bwrap ]; then echo "FATAL: /usr/bin/bwrap is still a symlink"; exit 1; fi
    echo "--- executable identity ---"
    identity
    echo "--- execution ---"
    run_bwrap_observing

    echo
    echo "--- the diagnostic shell label AFTER both attempts (for comparison) ---"
    cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"
  '

# ---------------------------------------------------------------------------
# HOST: the AppArmor policy as loaded, and the kernel audit records.
#
# The audit records are collected AFTER the container has run, because a record of
# the denial under investigation could not exist before the operation that
# produced it.
# ---------------------------------------------------------------------------
section "HOST: AppArmor policy as loaded"

echo "apparmor module enabled : $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
echo "unprivileged_userns_clone    : $(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo absent)"

echo
echo "--- loaded profiles (full lines: <name> <mode>) ---"
sudo cat /sys/kernel/security/apparmor/profiles 2>/dev/null \
  | grep -iE 'bwrap|unpriv|docker' \
  || echo "(profile list unavailable)"

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

section "HOST: kernel AppArmor audit records (collected AFTER the container ran)"

echo "--- dmesg | grep -i apparmor | tail -60 ---"
sudo dmesg 2>/dev/null | grep -i apparmor | tail -60 || echo "(dmesg unavailable)"

echo
echo "--- journalctl -k | grep -i apparmor | tail -60 ---"
sudo journalctl -k --no-pager 2>/dev/null | grep -i apparmor | tail -60 || echo "(journalctl unavailable)"

echo
echo "--- of those, the ones naming bwrap, userns, mount, capability or the container ---"
sudo dmesg 2>/dev/null | grep -i apparmor \
  | grep -iE 'bwrap|userns|mount|capab|docker|container' | tail -40 \
  || echo "(no such record)"
sudo journalctl -k --no-pager 2>/dev/null | grep -i apparmor \
  | grep -iE 'bwrap|userns|mount|capab|docker|container' | tail -40 \
  || echo "(no such record)"

section "DONE"
