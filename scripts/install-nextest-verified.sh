#!/usr/bin/env bash
#
# Install cargo-nextest into a job-local bin directory, from a pinned release, verified.
#
# # What this replaces
#
#     curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C /usr/local/cargo/bin
#
# That line, run as root on every push, was three defects at once (S-24, finding F-20):
#
#   * **Mutable.** `/latest/linux` resolves to whatever upstream chose most recently. The
#     lane's behaviour changed whenever upstream published, with no diff in this
#     repository to review.
#   * **Unauthenticated.** Nothing tied the bytes to an expected release, so a changed or
#     substituted artifact was installed silently.
#   * **Installed as root, into a system path, from a pipe.** `curl | tar` hands the
#     extractor whatever the network produced, with no point at which the content could be
#     checked, and `/usr/local/cargo/bin` is on PATH for everything else in the image.
#
# # What replaces it
#
# A pinned version, a pinned SHA-256, a download to a file, verification **before** the
# bytes are extracted, and an install into a directory the caller owns rather than a
# system path.
#
# # The pins, and where they come from
#
# `cargo-nextest` 0.9.146, target `x86_64-unknown-linux-gnu`.
#
# The checksum is the one published **with the release**, at
#   https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.146/
#     cargo-nextest-0.9.146-x86_64-unknown-linux-gnu.sha256
# which reads
#   682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428
# It was confirmed against the artifact itself (downloaded from the release and hashed
# locally) rather than copied from the index page, so the two agreeing is evidence rather
# than an assumption. **This value is a literal and is deliberately not overridable from
# the environment**: an overrideable checksum is not a checksum, it is a suggestion.
#
# **Why 0.9.146 and not the newest release.** `.github/workflows/ci.yml` already pins
# cargo-nextest to 0.9.146 and records why: the `taiki-e/install-action` manifest carries
# hashes only up to that version, and the two-release gap (0.9.147, 0.9.148) is
# stress-run exit-code corrections and dependency bumps that no gate depends on. Pinning
# this installer to the same version keeps **one** cargo-nextest in the project, so a test
# cannot pass in the container and fail in the gates. That comment's ceiling applies to
# the action's manifest, not to a direct release download, so the newer version was
# available -- choosing to match was a decision, not a constraint.
#
# # Why a mirror override is allowed but a checksum override is not
#
# `ORXNUD_NEXTEST_BASE_URL` may point the download at a mirror or an internal cache,
# which the plan asks for ("offline/mirror path still works"). That is safe *because the
# checksum pin still governs*: the mirror can change where bytes come from, never what
# they must be. An artifact served from anywhere that does not hash to the pin is
# rejected, which is the property that makes mirroring usable at all. There is
# deliberately no environment override for `NEXTEST_SHA256`.
#
# # Least privilege
#
# The caller is expected to run this **as the unprivileged user that will execute the
# binary**, with `TMPDIR` pointing at a directory that user owns.
# `run-sandbox-tests.sh` does exactly that, via `setpriv`, so the downloaded executable is
# never installed by root and never runs as root.
#
# # Failure is failure
#
# A missing pin, a download error, a checksum mismatch, a missing `sha256sum`, or a tar
# that does not contain the expected binary all exit nonzero, and none of them leave an
# installed binary behind. There is no `--force`, no `|| true`, and no degraded mode: a
# lane that cannot prove what it installed must not build or run tests with it.

set -euo pipefail

# Pinned, and literal. Not `:-`, not `${...}`: see the note above.
NEXTEST_VERSION="0.9.146"
NEXTEST_TARGET="x86_64-unknown-linux-gnu"
NEXTEST_SHA256="682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428"

BASE_URL="${ORXNUD_NEXTEST_BASE_URL:-https://github.com/nextest-rs/nextest/releases/download}"

die() { printf 'install-nextest: %s\n' "$1" >&2; exit 1; }

# --- arguments --------------------------------------------------------------
install_dir="${1:-}"
[ -n "$install_dir" ] || die "usage: $0 <install-dir>"
[ -d "$install_dir" ] || die "install directory does not exist: $install_dir"

# --- tools ------------------------------------------------------------------
# `sha256sum` is the whole point of this script. If it is missing, failing is correct:
# there is no fallback that verifies, and pretending otherwise would be the defect this
# replaces.
for tool in curl tar sha256sum install; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

# Already present and the right version? Nothing to do. Anything else is (re)installed,
# because a *different* version on PATH is not the version this file pins.
if [ -x "$install_dir/cargo-nextest" ] \
   && "$install_dir/cargo-nextest" --version 2>/dev/null | grep -q "$NEXTEST_VERSION"; then
  printf 'install-nextest: %s already at %s\n' "$NEXTEST_VERSION" "$install_dir/cargo-nextest"
  exit 0
fi

# --- work area --------------------------------------------------------------
# A private directory, removed on every exit path. `mktemp -d` on $TMPDIR, so an
# unprivileged caller is not fighting root for a location in /tmp.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/orxnud-nextest.XXXXXX")" \
  || die "could not create a work directory under ${TMPDIR:-/tmp}"
trap 'rm -rf "$tmp"' EXIT

archive="$tmp/cargo-nextest.tar.gz"
# The release asset name repeats the version *and* the target. Getting this wrong is a
# 404 that no offline test would notice, because a stubbed downloader does not care what
# URL it was asked for -- so `test-ci-toolchain-pinning.sh` asserts this exact string.
asset="cargo-nextest-$NEXTEST_VERSION-$NEXTEST_TARGET.tar.gz"
url="$BASE_URL/cargo-nextest-$NEXTEST_VERSION/$asset"

# --- download ---------------------------------------------------------------
# To a file. Never into a pipe: a piped download cannot be checked between arrival and
# use, which is the failure this script exists to remove.
printf 'install-nextest: downloading %s\n' "$url"
if ! curl --silent --show-error --fail --location \
          --proto '=https' --tlsv1.2 \
          --retry 3 --retry-delay 2 \
          -o "$archive" "$url"; then
  die "download failed: $url"
fi

[ -s "$archive" ] || die "downloaded artifact is empty: $url"

# --- verify, before anything is extracted or run ----------------------------
actual="$(sha256sum "$archive" | cut -d' ' -f1)"
if [ "$actual" != "$NEXTEST_SHA256" ]; then
  die "checksum mismatch for $url
         expected: $NEXTEST_SHA256
         actual:   $actual
         refusing to extract, install or run this artifact."
fi
printf 'install-nextest: checksum verified (%s)\n' "$NEXTEST_SHA256"

# --- extract ---------------------------------------------------------------
extract="$tmp/extract"
mkdir -p "$extract"
tar xzf "$archive" -C "$extract" || die "the verified archive did not extract"

binary="$(find "$extract" -type f -name cargo-nextest -print -quit)"
[ -n "$binary" ] || die "the verified archive contains no cargo-nextest binary"

# --- install ---------------------------------------------------------------
# Into the caller's directory, mode 0755, never a system path and never as root unless
# the caller chose to be root.
install -m 0755 "$binary" "$install_dir/cargo-nextest" \
  || die "could not install into $install_dir"

printf 'install-nextest: installed %s to %s/cargo-nextest\n' "$NEXTEST_VERSION" "$install_dir"
