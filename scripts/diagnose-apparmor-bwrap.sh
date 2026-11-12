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
# # The question being asked
#
# When bubblewrap is executed from a process confined by `docker-default`, does it enter
# the `bwrap` profile -- and why does its user-namespace creation fail?
#
# The answer has to come from the PROCESS, not from the profile file. An attachment path
# in a profile does not by itself establish a transition: a process already confined by
# another profile does not automatically enter another one. So the label of the bubblewrap
# process itself is read, from `/proc/<pid>/attr/current`, while it is alive.
#
# # Reproducing the production caller identity
#
# The caller identity is the thing that decides bubblewrap behaviour, so it must be
# reproduced exactly. Bubblewrap 0.13.1 contains:
#
#     if (getuid () != 0 && opt_userns_fd == -1)
#       opt_unshare_user = true;
#
# and it adds `CLONE_NEWUSER` to its `clone()` flags only when `opt_unshare_user` is
# true. So as ROOT it does NOT request a user namespace at all, and its `clone()` fails
# with a generic error; as an unprivileged uid it DOES request one, and a refusal is
# reported with an explicit message. The two are different operations and only the second
# is the one the product performs.
#
# This script therefore runs bubblewrap through the SAME `setpriv` invocation the
# production lane uses: uid 1000, gid 1000, no supplementary groups, no inheritable
# capabilities, an empty bounding set.
#
# # How the label is observed
#
# Three runs are made, and their results are reported separately.
#
# 1. ORDINARY -- the production invocation, no instrumentation. Its stderr is what
#    distinguishes the hypotheses: bubblewrap reports an explicit "No permissions to
#    create a new namespace..." when it REQUESTED a user namespace and was refused
#    (bubblewrap.c:3123), and a generic "Creating new namespace failed: ..." when it
#    did not request one (:3129). The two are different operations, and only the first
#    is the one the product performs.
#
# 2. OBSERVED -- the same production invocation, with the label of the bubblewrap
#    PROCESS read from `/proc/<pid>/attr/current` while that process is alive, and
#    `/proc/<pid>/comm` used to prove the process really is bubblewrap. The process
#    exists from execve until its failing clone(), which is a short window; a tight
#    loop with no forks in it can catch it.
#
#    Any non-empty label is recorded. A label equal to the label of the shell is a
#    RESULT -- "the process ran and inherited docker-default" -- and is not discarded.
#    The label is read from the /proc entry of the PROCESS, not of its parent: a child
#    does not inherit the label of the parent merely by being forked.
#
# 3. HANDSHAKE -- an INSTRUMENTED run that adds `--userns-block-fd`, which makes
#    bubblewrap block in the parent branch right after the clone that creates the
#    namespaces (:3115) and before the child writes the uid map (:3267) and makes its
#    mounts (:3280). This is the widest window available.
#
#    DISCLOSED LIMITATION: `--userns-block-fd` requires an EXPLICIT `--unshare-user`
#    (the guard at :2953 runs BEFORE the getuid() auto-set at :2972) and also requires
#    `--info-fd`. The production invocation does not pass `--unshare-user`; it relies
#    on the auto-set. So this run is NOT the production invocation, and its result is
#    reported separately. It cannot by itself diagnose a failure that occurs before
#    the handshake -- but reaching the handshake at all proves the namespace clone
#    SUCCEEDED, because a refused clone dies at :3121/:3123 and never gets there.
#
# # What this does NOT do
#
# Nothing here changes the security posture. It does not load or unload a profile, does
# not write a sysctl, does not add a capability, does not use a privileged container, and
# does not pass `apparmor=unconfined`. Every command is a read, a copy, or an attempt to
# execute something that is already installed.
#
# Kernel messages are collected from the HOST, never from inside the container: the
# kernel restricts `dmesg` to processes holding `CAP_SYSLOG`, and adding it would be a
# capability change. They are collected AFTER the container has run, because a record of
# the denial under investigation could not exist before the operation that produced it.
#
# # The two configurations compared
#
# **A. The current installation** -- the real binary at `/usr/local/bin/bwrap` with
#    `/usr/bin/bwrap` a verified symlink to it, exactly as `scripts/run-sandbox-tests.sh`
#    creates it.
# **B. The candidate installation** -- the SAME bytes at a regular `/usr/bin/bwrap`.
#
# Both run in the same container, as the same uid, with the same confinement and the same
# bubblewrap binary, and both are invoked as an EXPLICIT `/usr/bin/bwrap` path so the
# executable under test is never in doubt. Only the path the kernel sees differs.

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

    # The unprivileged user the production lane runs the tests as.
    id -u orxnud >/dev/null 2>&1 || useradd --create-home --uid 1000 orxnud

    # The argv the PRODUCT builds, reproduced here. `build_command` does NOT pass
    # `--unshare-user`: bubblewrap creates the user namespace itself when it is
    # unprivileged. Passing it explicitly would measure a different invocation.
    #
    # The bind list mirrors `host_backed_bind_destinations()`, which is
    # `HOST_BACKED_BIND_CANDIDATES` filtered by what exists on the host:
    # /usr, /lib, /lib64, /bin, /sbin.
    BW_ARGV=(
      --unshare-pid
      --unshare-ipc
      --unshare-uts
      --unshare-cgroup
      --die-with-parent
      --unshare-net
      --tmpfs /tmp
      --ro-bind /usr /usr
      --ro-bind /lib /lib
      --ro-bind /lib64 /lib64
      --ro-bind /bin /bin
      --ro-bind /sbin /sbin
    )

    # The exact identity the production lane uses.
    RUN_AS_USER=(setpriv --reuid=1000 --regid=1000 --clear-groups
                 --inh-caps=-all --bounding-set=-all --)

    identity() {
      echo "  /usr/bin/bwrap is a symlink? $( [ -L /usr/bin/bwrap ] && echo YES || echo no )"
      echo "  readlink -f /usr/bin/bwrap : $(readlink -f /usr/bin/bwrap 2>/dev/null || echo absent)"
      echo "  sha256 of /usr/bin/bwrap (resolved) : $(sha256sum /usr/bin/bwrap 2>/dev/null | cut -d" " -f1)"
      echo "  sha256 of the built binary         : $(sha256sum "$BW_BIN" | cut -d" " -f1)"
      stat -c "  stat %n  mode=%a  size=%s  inode=%i  links=%h" /usr/bin/bwrap 2>/dev/null || true
      stat -c "  stat %n  mode=%a  size=%s  inode=%i  links=%h" "$BW_BIN" 2>/dev/null || true
    }

    # Runs bubblewrap as the production uid and reports what happened.
    #
    # ORDINARY RUN: no instrumentation at all. The stderr is what distinguishes the
    # hypotheses: bubblewrap emits an explicit "No permissions to create a new
    # namespace..." message when it REQUESTED a user namespace and was refused, and a
    # generic "Creating new namespace failed: ..." when it did not request one.
    ordinary_run() {
      echo "  --- ordinary run (no instrumentation) ---"
      "${RUN_AS_USER[@]}" env HOME=/home/orxnud PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        /usr/bin/bwrap "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err
      echo "  exit status       : $?"
      echo "  bubblewrap stderr : $(head -3 /tmp/bw.err 2>/dev/null)"
    }

    # OBSERVED RUN: the ordinary, production invocation, with the label of the
    # bubblewrap PROCESS read from /proc while that process is alive.
    #
    # The process exists from execve until its failing clone(), which is a short
    # window. A tight loop with no forks in it can still catch it. The two rules
    # that matter:
    #
    #   * ANY non-empty label is recorded. A label equal to the label of the
    #     RESULT -- "the process ran and inherited docker-default" -- and must not
    #     be discarded. Rejecting it is what made the previous run report NOT
    #     OBSERVED for what may have been an observation.
    #   * the reader is the /proc entry of the PROCESS itself, not that of
    #     the parent. A child does not inherit the parent label merely by
    #
    # /proc/<pid>/comm is used to prove the process is bubblewrap, so a read
    # taken before the exec is not mistaken for one taken after it.
    observed_run() {
      echo "  --- observed run (production argv, label read from the process) ---"
      local label="" capeff="" comm="" seen=0 attempts=0 rc=0
      for try in $(seq 1 80); do
        attempts=$((attempts + 1))
        "${RUN_AS_USER[@]}" env HOME=/home/orxnud PATH=/usr/bin:/bin:/usr/sbin:/sbin \
          /usr/bin/bwrap "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err &
        local pid=$!
        # Tight loop: builtin reads only, no forks.
        local i
        for i in $(seq 1 3000); do
          if [ -r "/proc/$pid/comm" ]; then
            comm=""; read -r comm < "/proc/$pid/comm" 2>/dev/null || true
            if [ "$comm" = "bwrap" ]; then
              local l
              l=""; read -r l < "/proc/$pid/attr/current" 2>/dev/null || true
              if [ -n "$l" ]; then
                label="$l"; seen=1
                while read -r _k _v; do [ "$_k" = "CapEff:" ] && capeff="$_v"; done \
                  < "/proc/$pid/status" 2>/dev/null
                break
              fi
            fi
          fi
          kill -0 "$pid" 2>/dev/null || break
        done
        rc=0; wait "$pid" 2>/dev/null || rc=$?
        if [ "$seen" = "1" ]; then
          echo "  bubblewrap AppArmor label : $label"
          echo "  label == the shell label?  : $( [ "$label" = "$SHELL_LABEL" ] && echo YES || echo no )"
          echo "  bubblewrap CapEff        : ${capeff:-NOT OBSERVED}"
          echo "  bubblewrap comm           : ${comm:-NOT OBSERVED}"
          echo "  exit status       : $rc"
          echo "  bubblewrap stderr : $(head -3 /tmp/bw.err 2>/dev/null)"
          echo "  (label observed on attempt $attempts)"
          return 0
        fi
      done
      echo "  bubblewrap AppArmor label : NOT OBSERVED after $attempts attempts"
      echo "  (the process could not be read; this is NOT evidence that no profile applied)"
      echo "  exit status       : $rc"
      echo "  bubblewrap stderr : $(head -3 /tmp/bw.err 2>/dev/null)"
      return 1
    }

    # HANDSHAKE RUN: `--userns-block-fd` makes bubblewrap block in the PARENT
    # branch, right after the clone that creates the namespaces
    # (bubblewrap.c:3115) and before the CHILD writes the uid map (:3267) and
    # makes its mounts (:3280). So the process is alive, past the exec
    # transition, and past the namespace clone.
    #
    # The parent is the process whose /proc entry is read here. After a
    # successful CLONE_NEWUSER the uid of the parent in the new namespace is
    # unmapped until the map is written, so its Uid line shows that. If the
    # clone had been REFUSED, bubblewrap would have died at :3121/:3123 with
    # an explicit message and would never reach this point at all -- which is
    # why the handshake run ALSO reports the stderr.
    #
    # DISCLOSED LIMITATION: bubblewrap requires `--userns-block-fd` to be paired
    # with an EXPLICIT `--unshare-user` (the guard at bubblewrap.c:2953 runs BEFORE
    # the getuid() auto-set at :2972), and also requires `--info-fd`. The
    # production invocation does NOT pass `--unshare-user` -- it relies on the
    # auto-set. So this run is NOT the production invocation, and its result is
    # reported separately as an instrumented observation. It cannot by itself
    # diagnose a failure that occurs before the handshake.
    handshake_run() {
      echo "  --- handshake run (INSTRUMENTED: --userns-block-fd + explicit --unshare-user) ---"
      rm -f /tmp/userns.fifo /tmp/info.fifo; mkfifo /tmp/userns.fifo; mkfifo /tmp/info.fifo
      exec 3<>/tmp/userns.fifo
      exec 4<>/tmp/info.fifo
      "${RUN_AS_USER[@]}" env HOME=/home/orxnud PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        /usr/bin/bwrap --userns-block-fd 3 --info-fd 4 --unshare-user \
        "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err &
      local pid=$!
      local label="" capeff="" comm="" uidline=""
      for i in $(seq 1 600); do
        if [ -r "/proc/$pid/comm" ]; then
          comm=""; read -r comm < "/proc/$pid/comm" 2>/dev/null || true
          if [ "$comm" = "bwrap" ]; then
            local l
            l=""; read -r l < "/proc/$pid/attr/current" 2>/dev/null || true
            if [ -n "$l" ]; then
              label="$l"
              while read -r _k _v; do
                [ "$_k" = "CapEff:" ] && capeff="$_v"
                [ "$_k" = "Uid:" ] && uidline="$_v"
              done < "/proc/$pid/status" 2>/dev/null
              break
            fi
          fi
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.01
      done
      echo "  bubblewrap AppArmor label : ${label:-NOT OBSERVED}"
      if [ -n "$label" ]; then
        echo "  label == the shell label?  : $( [ "$label" = "$SHELL_LABEL" ] && echo YES || echo no )"
      fi
      echo "  bubblewrap CapEff        : ${capeff:-NOT OBSERVED}"
      echo "  bubblewrap Uid           : ${uidline:-NOT OBSERVED}"
      echo "  (the handshake is reached only if the namespace clone SUCCEEDED)"
      # Release the handshake and let it finish, so the mount failure is still seen.
      printf "x" >&3 2>/dev/null || true
      exec 3>&- 2>/dev/null || true
      exec 4>&- 2>/dev/null || true
      local rc=0; wait "$pid" 2>/dev/null || rc=$?
      echo "  exit status       : $rc"
      echo "  bubblewrap stderr : $(head -3 /tmp/bw.err 2>/dev/null)"
      rm -f /tmp/userns.fifo /tmp/info.fifo
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
    echo "--- caller identity (as the production lane runs it) ---"
    "${RUN_AS_USER[@]}" id 2>/dev/null | sed "s/^/  /"
    "${RUN_AS_USER[@]}" sh -c "awk \"/^CapEff:/{print \\\"  CapEff: \\\" \\\$2}\" /proc/self/status" 2>/dev/null
    ordinary_run
    observed_run
    handshake_run

    # ================= CONFIGURATION B: the candidate installation =================
    echo
    echo "################ CONFIGURATION B: the CANDIDATE installation ################"
    echo "# The SAME bytes at a REGULAR /usr/bin/bwrap. Only the path the kernel"
    echo "# sees differs; the bytes, the caller, the container and the confinement do not."
    rm -f /usr/bin/bwrap
    cp "$BW_BIN" /usr/bin/bwrap
    chmod 0755 /usr/bin/bwrap
    if [ -L /usr/bin/bwrap ]; then echo "FATAL: /usr/bin/bwrap is still a symlink"; exit 1; fi
    echo "--- executable identity ---"
    identity
    ordinary_run
    observed_run
    handshake_run

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
ls -1 /etc/apparmor.d/ 2>/dev/null | grep -iE "bwrap|unpriv" || echo "(none)"

echo
echo "--- the content of bwrap-userns-restrict (attachment + permissions) ---"
# docker-default is included because it is the confinement the CONTAINER runs under,
# and the container label was observed to be "docker-default (enforce)". Whether it
# grants `mount`/`userns`/`capability` is directly relevant to the question.
for f in /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/unprivileged_userns \
         /etc/apparmor.d/docker-default; do
  if [ -r "$f" ]; then
    echo "### $f"
    cat "$f"
  else
    echo "### $f : (not readable on this host)"
  fi
done

echo
echo "--- the /proc/self/attr/current of the host runner (the runner label) ---"
cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"

section "HOST: kernel AppArmor audit records (collected AFTER the container ran)"

echo "--- dmesg | grep -i apparmor | tail -60 ---"
sudo dmesg 2>/dev/null | grep -i apparmor | tail -60 || echo "(dmesg unavailable)"

echo
echo "--- journalctl -k | grep -i apparmor | tail -60 ---"
sudo journalctl -k --no-pager 2>/dev/null | grep -i apparmor | tail -60 || echo "(journalctl unavailable)"

echo
echo "--- of those, the ones naming bwrap, userns, mount, capability, clone or the container ---"
sudo dmesg 2>/dev/null | grep -i apparmor \
  | grep -iE 'bwrap|userns|mount|capab|clone|docker|container' | tail -40 \
  || echo "(no such record)"
sudo journalctl -k --no-pager 2>/dev/null | grep -i apparmor \
  | grep -iE 'bwrap|userns|mount|capab|clone|docker|container' | tail -40 \
  || echo "(no such record)"

section "DONE"
