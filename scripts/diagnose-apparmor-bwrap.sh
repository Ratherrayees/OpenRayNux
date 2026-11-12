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
# SELF-CHECK: the blocks below are passed to `bash` as single quoted strings, so
# an apostrophe inside one TERMINATES that string. `bash -n` on this file cannot
# see it -- the contents are just a string here -- so the mistake survives every
# local check and shows up only as a container that exits 2 with no explanation.
# That has happened twice on this branch.
#
# Each block is therefore extracted and checked for BOTH properties:
#   1. it contains no apostrophe at all, so it can be embedded in a single quoted
#      string safely; and
#   2. it is valid bash on its own.
# ---------------------------------------------------------------------------
check_quoted_block() {
  local open_re="$1" close_re="$2" label="$3"
  local tmp start end body
  tmp=$(mktemp)
  start=$(grep -nE "$open_re" "$0" | head -1 | cut -d: -f1)
  if [ -z "$start" ]; then
    echo "FATAL: could not locate the $label block inside $0" >&2
    rm -f "$tmp"; exit 1
  fi
  end=$(awk -v s="$start" -v re="$close_re" \
        'NR>s && $0 ~ re {print NR; exit}' "$0")
  if [ -z "$end" ]; then
    echo "FATAL: could not locate the end of the $label block inside $0" >&2
    rm -f "$tmp"; exit 1
  fi
  body=$(sed -n "$((start + 1)),$((end - 1))p" "$0")
  if printf '%s' "$body" | grep -q "'"; then
    echo "FATAL: the $label block (lines $((start + 1))-$((end - 1)) of $0) contains an apostrophe." >&2
    echo "       It is embedded in a single quoted string, so the apostrophe would end it." >&2
    printf '%s' "$body" | grep -n "'" >&2
    rm -f "$tmp"; exit 1
  fi
  printf '%s' "$body" > "$tmp"
  if ! bash -n "$tmp"; then
    echo "FATAL: the $label block (lines $((start + 1))-$((end - 1)) of $0) is not valid bash." >&2
    rm -f "$tmp"; exit 1
  fi
  rm -f "$tmp"
  echo "self-check: the $label block is free of apostrophes and is valid bash"
}
check_quoted_block "bash -lc '[^']*$" "^[[:space:]]*'[[:space:]]*$" "container"
check_quoted_block "bash -c '[^']*$" "^[[:space:]]*'" "host control"

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
    # The DISTRO bubblewrap as well as the pinned build. Configuration C runs the two
    # under the same confinement, which is what separates "the confinement refuses it"
    # from "this bubblewrap version refuses it". The package is installed from the
    # base image own repository and changes nothing about the confinement.
    apt-get install -y -qq bubblewrap >/dev/null 2>&1 || true
    # The distro bubblewrap is preserved under its own name BEFORE /usr/bin/bwrap is
    # overwritten below, because the configurations that follow replace it. Without
    # this, configuration C would silently compare the pinned build with itself.
    DISTRO_BWRAP_SAVED="/usr/local/bin/bwrap-distro"
    if command -v bwrap >/dev/null 2>&1; then
      cp "$(command -v bwrap)" "$DISTRO_BWRAP_SAVED"
      echo "distro bubblewrap preserved: $DISTRO_BWRAP_SAVED"
    else
      echo "(no distro bubblewrap on this base image)"
    fi
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
    # Helpers: the nested quoting of a command substitution inside a
    # double quoted string is easy to get wrong, so it is done once here.
    ver_of() { "$1" --version 2>/dev/null || echo "(not reported)"; }
    sha_of() { sha256sum "$1" 2>/dev/null | cut -d" " -f1; }

    ordinary_run() {
      echo "  --- ordinary run (no instrumentation) ---"
      "${RUN_AS_USER[@]}" env HOME=/home/orxnud PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "${BW_EXEC:-/usr/bin/bwrap}" "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err
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
          "${BW_EXEC:-/usr/bin/bwrap}" "${BW_ARGV[@]}" -- /bin/true >/tmp/bw.out 2>/tmp/bw.err &
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

    echo
    echo "################ CONFIGURATION C: a DIFFERENT bubblewrap build ################"
    echo "# The container has been shown to fail with the PINNED 0.13.1 binary, and the"
    echo "# host has been shown to succeed with the distro binary. Those two differ in"
    echo "# TWO ways at once: the confinement, and the bubblewrap version. This"
    echo "# configuration holds the confinement fixed and changes only the binary: the"
    echo "# distro bubblewrap, run here under docker-default exactly as the pinned one"
    echo "# was."
    echo "# If the distro binary ALSO fails here, the version is not what matters."
    echo "# If it SUCCEEDS here, the version is what matters, and the host result was"
    echo "# never comparable to begin with."
    echo
    echo "--- the distro bubblewrap, as the base image ships it ---"
    if [ -x "$DISTRO_BWRAP_SAVED" ]; then
      DISTRO_BWRAP="$DISTRO_BWRAP_SAVED"
      echo "  path    : $DISTRO_BWRAP"
      echo "  version : $(ver_of "$DISTRO_BWRAP")"
      echo "  sha256  : $(sha_of "$DISTRO_BWRAP")"
      BW_EXEC="$DISTRO_BWRAP"
      ordinary_run
      observed_run
      echo
      echo "--- the PINNED binary, for the side-by-side in the same confinement ---"
      echo "  version : $(ver_of "$BW_BIN")"
      echo "  sha256  : $(sha_of "$BW_BIN")"
      BW_EXEC="$BW_BIN"
      ordinary_run
    else
      echo "  (no distro bubblewrap on this image; the version cannot be separated here)"
    fi

    echo
    echo "--- the CONTAINER mount table (the tree bubblewrap has to re-mount) ---"
    # bubblewrap makes "/" a slave mount at bubblewrap.c:3280, and that is where it
    # fails in the container. Whether it can depends on the mount tree it inherits,
    # so the tree is reported. "locked" appears in mountinfo for a mount the
    # container may not change the propagation of.
    cat /proc/self/mountinfo 2>/dev/null | head -40 || echo "(mountinfo unavailable)"
    echo "--- the number of mounts in the container ---"
    wc -l < /proc/self/mountinfo 2>/dev/null || echo "(mountinfo unavailable)"
    echo "--- the AppArmor label of the container shell, and the container uid_map ---"
    cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"
    cat /proc/self/uid_map 2>/dev/null || echo "(uid_map unavailable)"
  '

# ---------------------------------------------------------------------------
# HOST: the same bubblewrap, the same caller, run ON THE HOST.
#
# The host is where the lane DOES sandbox, so it is the control. Running the same
# binary as the same uid on the host and observing the same three things -- the
# stderr, the AppArmor label of the bubblewrap process, and its capability state --
# is what turns "the container differs" into "the container differs IN THIS WAY".
#
# The host already has bubblewrap installed by the image at /usr/bin/bwrap, which is
# the path the `bwrap` AppArmor profile is attached to. That is the whole question:
# does the process enter that profile here, and does it fail to in the container?
#
# Read-only: this runs the already-installed binary as an already-existing
# unprivileged user. It writes nothing, changes no policy and adds no capability.
# ---------------------------------------------------------------------------
section "HOST: the same operation, run ON THE HOST (the control)"

HOST_BWRAP=""
for candidate in /usr/bin/bwrap /usr/local/bin/bwrap; do
  if [ -x "$candidate" ]; then HOST_BWRAP="$candidate"; break; fi
done

if [ -z "$HOST_BWRAP" ]; then
  echo "no bubblewrap on this host; the control cannot be run here"
else
  echo "host bubblewrap   : $HOST_BWRAP"
  echo "host bwrap version: $("$HOST_BWRAP" --version 2>/dev/null || echo "(not reported)")"
  echo "host bwrap sha256 : $(sha256sum "$HOST_BWRAP" 2>/dev/null | cut -d' ' -f1)"
  echo "host bwrap is a symlink? $( [ -L "$HOST_BWRAP" ] && echo YES || echo no )"

  # The uid to run as. The host lane uses uid 1000; if it does not exist on this
  # host the run is skipped rather than performed as root, because running as root
  # is a DIFFERENT operation (see the getuid() note in the header).
  if id -u 1000 >/dev/null 2>&1; then
    HOST_UID=1000
  else
    HOST_UID=$(id -u)
    echo "uid 1000 does not exist on this host; using uid $HOST_UID instead"
  fi

  echo
  echo "--- the host run, as the production lane runs it ---"
  echo "  --- ordinary run (no instrumentation) ---"
  # The status is captured rather than allowed to abort the script: a NONZERO exit is
  # the expected result if the host also refuses, and the whole point is to record
  # what happened rather than to stop.
  host_rc=0
  sudo setpriv --reuid="$HOST_UID" --regid="$HOST_UID" --clear-groups \
       --inh-caps=-all --bounding-set=-all -- \
    env HOME=/tmp PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    "$HOST_BWRAP" --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
      --die-with-parent --unshare-net --tmpfs /tmp \
      --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /bin /bin --ro-bind /sbin /sbin -- /bin/true \
      >/tmp/host-bw.out 2>/tmp/host-bw.err || host_rc=$?
  echo "  exit status       : $host_rc"
  echo "  bubblewrap stderr : $(head -3 /tmp/host-bw.err 2>/dev/null)"

  echo
  echo "--- the AppArmor label of the bubblewrap PROCESS on the host ---"
  # The same read as in the container: the label of the process itself, taken while
  # it is alive, with /proc/<pid>/comm proving the process is bubblewrap. Any
  # non-empty label is recorded, including one equal to the label of the shell.
  #
  # This whole block runs under ONE `sudo`, because the process it observes runs as
  # a different uid and its /proc entries are not readable by the runner, and
  # because a `sudo` per iteration would be far too slow to catch the window.
  #
  # The handshake is used to widen the window, exactly as in the container: it is
  # the only reliable way to read the label of a process that exits in
  # milliseconds. It is disclosed as instrumented.
  sudo env HOST_UID="$HOST_UID" HOST_BWRAP="$HOST_BWRAP" bash -c '
    set -uo pipefail
    rm -f /tmp/host-userns.fifo /tmp/host-info.fifo
    mkfifo /tmp/host-userns.fifo; mkfifo /tmp/host-info.fifo
    exec 3<>/tmp/host-userns.fifo
    exec 4<>/tmp/host-info.fifo
    setpriv --reuid="$HOST_UID" --regid="$HOST_UID" --clear-groups \
         --inh-caps=-all --bounding-set=-all -- \
      env HOME=/tmp PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      "$HOST_BWRAP" --userns-block-fd 3 --info-fd 4 --unshare-user \
        --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup \
        --die-with-parent --unshare-net --tmpfs /tmp \
        --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
        --ro-bind /bin /bin --ro-bind /sbin /sbin -- /bin/true \
        >/tmp/host-bw.out 2>/tmp/host-bw.err &
    pid=$!
    label=""; capeff=""; comm=""; uidline=""
    for i in $(seq 1 3000); do
      if [ -r "/proc/$pid/comm" ]; then
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
        if [ "$comm" = "bwrap" ]; then
          l=$(cat "/proc/$pid/attr/current" 2>/dev/null || true)
          if [ -n "$l" ]; then
            label="$l"
            while read -r _k _v; do
              if [ "$_k" = "CapEff:" ]; then capeff="$_v"; fi
              if [ "$_k" = "Uid:" ]; then uidline="$_v"; fi
            done < "/proc/$pid/status" 2>/dev/null
            break
          fi
        fi
      fi
      kill -0 "$pid" 2>/dev/null || break
    done
    printf "x" >&3 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    exec 4>&- 2>/dev/null || true
    rc=0; wait "$pid" 2>/dev/null || rc=$?
    echo "  bubblewrap AppArmor label : ${label:-NOT OBSERVED}"
    echo "  bubblewrap CapEff        : ${capeff:-NOT OBSERVED}"
    echo "  bubblewrap comm           : ${comm:-NOT OBSERVED}"
    echo "  bubblewrap Uid           : ${uidline:-NOT OBSERVED}"
    echo "  exit status       : $rc"
    echo "  bubblewrap stderr : $(head -3 /tmp/host-bw.err 2>/dev/null)"
    rm -f /tmp/host-userns.fifo /tmp/host-info.fifo
  ' || echo "  (the host control run could not be completed)"

  echo
  echo "  THE COMPARISON: in the container the label was 'docker-default (enforce)';"
  echo "  here it is recorded above."
fi

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
# Read with sudo: docker-default is mode-restricted on Ubuntu, and it is the profile the
# CONTAINER runs under (its label was observed to be "docker-default (enforce)"). Whether
# it grants or denies `mount` decides whether the container can sandbox at all.
for f in /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/unprivileged_userns \
         /etc/apparmor.d/docker-default; do
  if sudo test -r "$f"; then
    echo "### $f"
    sudo cat "$f"
  else
    echo "### $f : (not readable on this host)"
  fi
done

echo
echo "--- the rules of the profile the CONTAINER runs under, as the kernel has them ---"
# The loaded policy, not the file: the file is a template and the loaded policy is what
# mediates. `aa-status` reads the loaded policy.
if command -v aa-status >/dev/null 2>&1; then
  sudo aa-status 2>/dev/null | grep -A 60 -i "docker-default" | head -70 \
    || echo "(aa-status produced no docker-default section)"
else
  echo "(aa-status is not installed on this host)"
fi

echo
echo "--- the docker-default TEMPLATE that the RUNNER's own dockerd embeds ---"
# The container's profile is GENERATED by the local dockerd from a template embedded
# in its binary, and the generated file is not left on disk. The daemon binary is
# therefore the authoritative record of what rule the container is confined by.
# This is read from the binary; nothing is loaded, changed or written.
DOCKERD_BIN=""
for c in /usr/bin/dockerd /usr/libexec/docker/dockerd /usr/local/bin/dockerd; do
  if [ -x "$c" ]; then DOCKERD_BIN="$c"; break; fi
done
if [ -z "$DOCKERD_BIN" ]; then
  echo "(no dockerd binary found on this host)"
else
  echo "  dockerd: $DOCKERD_BIN"
  echo "  version : $(sudo "$DOCKERD_BIN" --version 2>/dev/null || echo '(not reported)')"
  echo
  echo "  --- the mount / capability / umount rules in the embedded template ---"
  sudo strings -a "$DOCKERD_BIN" 2>/dev/null \
    | grep -nE '^[[:space:]]*(deny[[:space:]]+|allow[[:space:]]+)?(mount|umount|pivot_root|capability|userns)([[:space:]]*,|[[:space:]]*$)' \
    | head -20 || echo "(no matching lines)"
  echo
  echo "  --- the ABI line of the template ---"
  sudo strings -a "$DOCKERD_BIN" 2>/dev/null \
    | grep -E 'abi <\{\{\.Abi\}\}>|^\{\{if \.Abi\}\}' | head -3 \
    | sed 's/^/    /' || echo "(no ABI line found)"
  echo
  echo "  --- the ABI the daemon declares for the generated profile ---"
  # The template is `{{if .Abi}}abi <{{.Abi}}>,{{- end}}`; the literal below is the
  # value the daemon substitutes. The EFFECTIVE ABI is what the kernel applies, and
  # it is only the declared ABI if no override forces otherwise -- so the force
  # sysctls are read too, below.
  sudo strings -a "$DOCKERD_BIN" 2>/dev/null | grep -oE 'abi/[0-9]+\.[0-9]+' | sort -u \
    | sed 's/^/    declared ABI candidate: /' | head -5
fi

echo
echo "--- the userns restriction sysctls, including the FORCE and COMPLAIN overrides ---"
# These decide whether the declared ABI of a profile is actually enforced for user
# namespace creation. Without reading them, the ABI of the container profile is not
# established.
for s in apparmor_restrict_unprivileged_userns \
         apparmor_restrict_unprivileged_userns_force \
         apparmor_restrict_unprivileged_userns_complain; do
  printf "  %-46s = " "kernel.$s"
  cat "/proc/sys/kernel/$s" 2>/dev/null || echo "(absent on this kernel)"
done
echo "  (a FORCE value of 1 enforces userns mediation regardless of the declared ABI;"
echo "   COMPLAIN of 1 turns the denial into an ALLOWED record. Neither is 0 by default.)"

echo
echo "--- the /proc/self/attr/current of the host runner (the runner label) ---"
cat /proc/self/attr/current 2>/dev/null || echo "(unavailable)"

echo
echo "--- the HOST mount table (the tree bubblewrap has to re-mount there) ---"
# The container's tree and the host's tree are compared, because bubblewrap makes
# "/" a slave mount and that is where the container fails.
cat /proc/self/mountinfo 2>/dev/null | head -40 || echo "(mountinfo unavailable)"
echo "--- the number of mounts on the host ---"
wc -l < /proc/self/mountinfo 2>/dev/null || echo "(mountinfo unavailable)"

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

echo
echo "--- dmesg: EVERY apparmor record that is a DENIED, naming the profile ---"
# A denial inside the container is recorded in the HOST kernel ring buffer under the
# container's audit context, so it IS visible here. Looking for every DENIED rather
# than only the ones matching the earlier grep means a denial that does not mention
# bwrap by name is still visible.
sudo dmesg 2>/dev/null | grep -i 'apparmor="DENIED"' | tail -40 || echo "(no DENIED record)"
sudo journalctl -k --no-pager 2>/dev/null | grep -i 'apparmor="DENIED"' | tail -40 \
  || echo "(no DENIED record)"

echo
echo "--- dmesg: the records from the WINDOW in which the container ran ---"
# The container ran a few seconds ago. Anything recorded after the docker-default
# profile_load is from the container's own execution.
sudo dmesg 2>/dev/null | grep -iE 'apparmor|audit:' | tail -25 || echo "(none)"

section "DONE"
