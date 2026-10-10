#!/usr/bin/env bash
#
# S-24 negative tests: the CI toolchain installer must refuse before anything runs.
#
# # Why this is a script and not a Rust test
#
# The thing under test is a shell script that runs inside a container that CI starts.
# A Rust test could only reach it by re-implementing its logic, and a re-implementation
# is exactly what these tests must not be: they would keep passing while the production
# script stayed unverified. So these drive `scripts/install-nextest-verified.sh` itself
# and read `scripts/run-sandbox-tests.sh` itself. If the production path changes and stops
# verifying, these fail.
#
# # What "before anything runs" means here
#
# The supply-chain failure S-24 exists to prevent is: a wrong or tampered tool gets
# installed as root, and then the lane builds and runs tests with it. The ordering is
# therefore the property, not merely the final error code. These assert three things
# together -- nonzero exit, no installed binary, and no execution -- because a script that
# verified the checksum *after* installing would satisfy the first and fail the second.
#
# # Offline by design
#
# Every case here runs without the network. A bad artifact is produced locally and the
# downloader is stubbed, so the real verification code runs against bytes that genuinely
# do not match the pin. The *positive* path -- the real artifact verifying successfully --
# is exercised by the `sandbox-integration` lane itself on every run; a gate that
# re-downloaded 12 MB to prove it would be a network dependency in the gate set, which
# this repository does not take.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

INSTALLER="scripts/install-nextest-verified.sh"
SANDBOX="scripts/run-sandbox-tests.sh"
RESOURCE="scripts/run-resource-tests.sh"

pass=0
fail=0

ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail + 1)); }
banner() { printf '\033[1m%s\033[0m\n' "$1"; }

# Search only *executable* lines: a comment-only line is stripped first.
#
# Both production scripts deliberately quote the command S-24 removed, in the comment that
# explains why it was removed. A grep that counts those lines reports the documentation of
# a fix as the fix's presence, which would force the explanation to be deleted -- and the
# explanation is worth more than the grep. So a match has to be on a line that actually runs.
grep_code() {
  local pattern="$1"; shift
  local f found=0 missing=0
  for f in "$@"; do
    if [ ! -f "$f" ]; then
      printf '  \033[31mFAIL\033[0m  cannot search %s: file does not exist\n' "$f"
      missing=1
      continue
    fi
    grep -nE "$pattern" "$f" | grep -vE ':[[:space:]]*#' || true
    if grep -E "$pattern" "$f" | grep -qvE '^[[:space:]]*#'; then found=1; fi
  done
  [ "$missing" -eq 1 ] && return 2
  [ "$found" -eq 1 ] && return 0
  return 1
}

# Search a set of files for a pattern. Prints every match.
#
# `grep a b c` exits 2 when *any* argument is missing, even if it matched the others --
# which turns "the pattern is present" into a silent pass. That is a vacuous assertion
# wearing a check's clothes, so every file is required to exist first and a missing one
# is itself reported as a failure.
grep_all() {
  local pattern="$1"; shift
  local f found=0 missing=0
  for f in "$@"; do
    if [ ! -f "$f" ]; then
      printf '  \033[31mFAIL\033[0m  cannot search %s: file does not exist\n' "$f"
      missing=1
      continue
    fi
    grep -nE "$pattern" "$f" || true
    if grep -qE "$pattern" "$f"; then found=1; fi
  done
  [ "$missing" -eq 1 ] && return 2
  [ "$found" -eq 1 ] && return 0
  return 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# A stub `curl` that serves `$STUB_ARTIFACT` and records that it was called.
#
# Substituting the *source* of the bytes, not the checking of them: the production script's
# own verification runs against this content. That is what makes these tests negative
# tests of the production path rather than of a copy.
make_stub_curl() {
  mkdir -p "$TMP/stubbin"
  cat > "$TMP/stubbin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
echo "curl $*" >> "$STUB_LOG"
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
if [ -z "$out" ]; then
  # A caller that pipes us into something else: refuse loudly rather than pretend.
  echo "stub curl: refusing to serve on stdout; the installer must download to a file" >&2
  exit 64
fi
if [ "${STUB_MODE:-ok}" = "fail" ]; then
  echo "stub curl: simulated download failure" >&2
  exit 22
fi
cp "$STUB_ARTIFACT" "$out"
STUB
  chmod +x "$TMP/stubbin/curl"
}

# A tarball-shaped artifact whose bytes are deliberately NOT the pinned release.
make_bad_artifact() {
  local dir="$TMP/build"
  mkdir -p "$dir/cargo-nextest"
  printf '#!/bin/sh\necho "pwned"\n' > "$dir/cargo-nextest/cargo-nextest"
  chmod +x "$dir/cargo-nextest/cargo-nextest"
  tar czf "$TMP/bad.tar.gz" -C "$dir" cargo-nextest
}

# ---------------------------------------------------------------------------
banner "S-24: a wrong checksum fails before installation and before execution"
# ---------------------------------------------------------------------------

# The dynamic cases need the installer; the static cases below do not, and they are the
# ones that describe what is wrong with the tree *today*. Running them unconditionally is
# the point: a missing installer must not hide an unpinned image or a `curl | tar`.
INSTALLER_PRESENT=0
if [ -f "$INSTALLER" ]; then
  INSTALLER_PRESENT=1
else
  bad "$INSTALLER exists -- the CI toolchain path is unverified while this is absent"
fi

make_bad_artifact
make_stub_curl

export STUB_LOG="$TMP/curl.log"
export STUB_ARTIFACT="$TMP/bad.tar.gz"
export STUB_MODE="ok"
: > "$STUB_LOG"

if [ "$INSTALLER_PRESENT" -eq 1 ]; then
install_dir="$TMP/install"; mkdir -p "$install_dir"
set +e
PATH="$TMP/stubbin:$PATH" bash "$INSTALLER" "$install_dir" > "$TMP/out" 2> "$TMP/err"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  ok "a mismatched artifact exits nonzero (rc=$rc)"
else
  bad "a mismatched artifact exits nonzero (rc=$rc) -- the pin was not enforced"
fi

if [ ! -e "$install_dir/cargo-nextest" ]; then
  ok "nothing was installed into the job-local bin directory"
else
  bad "something was installed despite the mismatch -- verification runs too late"
fi

if grep -qiE 'checksum|sha256|mismatch|does not match' "$TMP/err" "$TMP/out"; then
  ok "the failure names the checksum rather than failing silently"
else
  bad "the failure must say the checksum did not match; got: $(tr '\n' ' ' < "$TMP/err" | head -c 200)"
fi

# The stub refuses to serve on stdout. If the installer ever pipes curl into tar again,
# this is where it dies -- and the test says so, rather than passing because the stub
# happened to cooperate.
if grep -q 'refusing to serve on stdout' "$TMP/err"; then
  bad "the installer piped the download into a command -- network content must land in a file"
else
  ok "the download was not piped into another command"
fi
fi

# ---------------------------------------------------------------------------
banner "S-24: a failed download fails closed"
# ---------------------------------------------------------------------------

export STUB_MODE="fail"
if [ "$INSTALLER_PRESENT" -eq 1 ]; then
install_dir2="$TMP/install2"; mkdir -p "$install_dir2"
: > "$STUB_LOG"
set +e
PATH="$TMP/stubbin:$PATH" bash "$INSTALLER" "$install_dir2" > "$TMP/out2" 2> "$TMP/err2"
rc2=$?
set -e

if [ "$rc2" -ne 0 ]; then
  ok "a failed download exits nonzero (rc=$rc2)"
else
  bad "a failed download exits nonzero (rc=$rc2) -- an empty or partial artifact was tolerated"
fi

if [ ! -e "$install_dir2/cargo-nextest" ]; then
  ok "nothing was installed after a failed download"
else
  bad "something was installed after a failed download"
fi
fi

# ---------------------------------------------------------------------------
banner "S-24: the production scripts are pinned and verified"
# ---------------------------------------------------------------------------

# The mutable feed is gone. `get.nexte.st/latest` resolves to whatever upstream chose
# most recently, which is precisely the unauthenticated root install this slice removes.
if grep_code 'get\.nexte\.st' "$SANDBOX" "$RESOURCE" >/dev/null 2>&1; then
  bad "the mutable get.nexte.st feed is gone from the CI toolchain path"
elif [ $? -eq 2 ]; then
  bad "the mutable get.nexte.st check could not run: a file is missing"
else
  ok "the mutable get.nexte.st feed is gone"
fi

# A pinned version must appear in the installer, and the download must come from a URL
# carrying that exact version rather than a `latest` alias.
if [ "$INSTALLER_PRESENT" -eq 0 ]; then
  bad "the installer must pin an exact nextest version"
elif grep -qE '^NEXTEST_VERSION="[0-9]+\.[0-9]+\.[0-9]+"' "$INSTALLER"; then
  ok "the installer pins an exact nextest version"
else
  bad "the installer must pin an exact nextest version"
fi

# The pin must be a literal. `NEXTEST_SHA256="${...}"` -- even defaulted -- would make the
# pin a suggestion, and a suggestion is what the old mutable feed was.
if grep_code 'NEXTEST_SHA256="(\$\{|\$)' "$INSTALLER" >/dev/null 2>&1; then
  bad "the checksum pin must be a literal, not an environment override"
elif [ $? -eq 2 ]; then
  bad "the pin-literal check could not run: the installer is missing"
else
  ok "the checksum pin is a literal, not an environment override"
fi

ver="$(sed -nE 's/^NEXTEST_VERSION="([^"]+)"/\1/p' "$INSTALLER" | head -1)"
tgt="$(sed -nE 's/^NEXTEST_TARGET="([^"]+)"/\1/p' "$INSTALLER" | head -1)"

# The URL the installer **actually requested**, read from the stub's log rather than from
# the source text.
#
# Both of those are wrong in different ways. Matching source text against a literal ignores
# that the URL is built from variables; and "does the source mention the version?" passed
# against a URL that returns 404, because the release asset name needs BOTH the version and
# the target (`cargo-nextest-0.9.146-x86_64-unknown-linux-gnu.tar.gz`). What the stub was
# asked for is the only version of this that cannot lie.
requested="$(sed -nE 's#.* (https?://[^ ]+)$#\1#p' "$STUB_LOG" | tail -1)"
expected_suffix="cargo-nextest-$ver/$ver-$tgt.tar.gz"
expected_suffix="cargo-nextest-$ver/cargo-nextest-$ver-$tgt.tar.gz"
if [ -n "$requested" ] && printf '%s' "$requested" | grep -q "$expected_suffix"; then
  ok "the installer requests the exact release asset ($ver / $tgt)"
else
  bad "the installer must request .../$expected_suffix; it asked for: ${requested:-<nothing>}"
fi

# And it must be HTTPS: a checksum is only as good as the path the bytes arrive over.
if [ -n "$requested" ] && printf '%s' "$requested" | grep -q '^https://'; then
  ok "the download is over HTTPS"
else
  bad "the download must be over HTTPS; requested: ${requested:-<nothing>}"
fi

# A 64-hex-character constant. A truncated or placeholder digest is a pin that looks
# pinned and is not.
if grep -qE '^NEXTEST_SHA256="[0-9a-f]{64}"$' "$INSTALLER"; then
  ok "the installer carries a well-formed SHA-256 pin"
else
  bad "the installer must carry a 64-hex-character NEXTEST_SHA256"
fi

# Container images pinned by registry manifest digest. `rust:1-bookworm` alone is a
# mutable tag; a local image ID is not a registry digest and would not survive a pull.
for f in "$SANDBOX" "$RESOURCE"; do
  if grep -qE '^IMAGE="\$\{[A-Z_]+:-rust:1-bookworm@sha256:[0-9a-f]{64}\}"' "$f"; then
    ok "$(basename "$f") pins rust:1-bookworm by registry digest"
  else
    bad "$(basename "$f") must default to rust:1-bookworm@sha256:<64 hex>"
  fi
done

# The installer must not run as root into a system path. `/usr/local/cargo/bin` is the
# path the old `curl | tar` wrote to, as root, on every push.
if grep_code 'curl[^|]*\|[[:space:]]*tar' "$SANDBOX" "$INSTALLER" >/dev/null 2>&1; then
  bad "no network content is piped into an extraction or install command"
elif [ $? -eq 2 ]; then
  bad "the pipe check could not run: a file is missing"
else
  ok "no network content is piped into an extraction or install command"
fi

# Nothing may *install into* the root-owned system bin directory. Naming it on PATH is
# fine and necessary -- it is the image's own cargo bin, where `cargo` lives -- so the
# check is for a write: `tar -C /usr/local/cargo/bin`, or `install ... /usr/local/cargo/bin`.
if grep_code '(-C[[:space:]]+[^[:space:]]*[[:space:]]*/usr/local/cargo/bin)|(install[^|]*/usr/local/cargo/bin)' \
     "$SANDBOX" "$INSTALLER" >/dev/null 2>&1; then
  bad "nothing installs into the root-owned system bin directory"
elif [ $? -eq 2 ]; then
  bad "the system-bin check could not run: a file is missing"
else
  ok "nothing installs into /usr/local/cargo/bin"
fi

# ---------------------------------------------------------------------------
echo
if [ "$fail" -eq 0 ]; then
  printf '  \033[32mall %d S-24 pinning checks passed\033[0m\n' "$pass"
  exit 0
fi
printf '  \033[31m%d S-24 pinning checks failed\033[0m (of %d)\n' "$fail" "$((pass + fail))"
exit 1
