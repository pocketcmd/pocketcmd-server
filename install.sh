#!/bin/sh
# PocketCmd installer.
#
#   curl -fsSL https://pocketcmd.com/install.sh | sh
#
# Downloads the release archive matching your OS/arch from GitHub Releases,
# verifies its SHA-256 against the signed checksums file, (optionally) verifies
# the cosign signature when `cosign` is installed, and installs the binary.
#
# Run it again to update: it replaces the installed pcmd in place, restarts its
# service if it is running, and puts the previous binary back if the new one
# fails its health check.
#
# Environment overrides (all optional):
#   PCMD_REPO             owner/name to install from
#                              (default: pocketcmd/pocketcmd-server)
#   PCMD_VERSION          release tag to install, e.g. v1.0.0
#                              (default: latest release)
#   PCMD_INSTALL_DIR      target directory for the binary
#                              (default: where pcmd already is, else
#                              /usr/local/bin, else ~/.local/bin)
#   PCMD_COSIGN_IDENTITY  cosign certificate-identity regexp
#   PCMD_BASE_URL         download directory containing the archives +
#                              checksums.txt (mirror, or a local dir served over
#                              HTTP). Bypasses GitHub Releases entirely.
set -eu

REPO="${PCMD_REPO:-pocketcmd/pocketcmd-server}"
VERSION="${PCMD_VERSION:-latest}"
BINARY="pcmd"
OIDC_ISSUER="${PCMD_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_IDENTITY="${PCMD_COSIGN_IDENTITY:-https://github.com/${REPO}/.*}"

info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }
need curl
need tar

[ $# -eq 0 ] || err "unknown argument: $1"

# --- existing install ------------------------------------------------------
# An update replaces the binary the service runs instead of adding a second
# copy in the default location.
EXISTING=""
if [ -z "${PCMD_INSTALL_DIR:-}" ]; then
  for p in "$(command -v "$BINARY" 2>/dev/null || true)" "/usr/local/bin/${BINARY}" "${HOME}/.local/bin/${BINARY}"; do
    case "$p" in /*) if [ -x "$p" ]; then EXISTING="$p"; break; fi ;; esac
  done
fi
if [ -n "$EXISTING" ]; then
  case "$(readlink "$EXISTING" 2>/dev/null || true)" in
    *Caskroom*) err "${EXISTING} is managed by Homebrew; update it with: brew upgrade --cask pocketcmd && ${BINARY} restart" ;;
  esac
fi

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) err "unsupported OS: $os (linux and macOS only)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64)        ARCH=amd64 ;;
  arm64 | aarch64)       ARCH=arm64 ;;
  *) err "unsupported architecture: $arch (amd64 and arm64 only)" ;;
esac

# A shell running under Rosetta on Apple Silicon reports x86_64; install the
# native arm64 build there instead of the translated Intel one.
if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ] &&
   [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = 1 ]; then
  ARCH=arm64
fi

# Archives keep the product name; the binary inside is pcmd.
ARCHIVE="pocketcmd_${OS}_${ARCH}.tar.gz"

fetch() { # fetch <url> <output-file>
  curl -fsSL -o "$2" "$1"
}

# --- resolve download location ---------------------------------------------
# The highest stable release. Highest by number, not newest upload, so a
# hotfix cut for an older line never shadows a newer release. In each release
# object tag_name comes before prerelease; drafts are not listed publicly.
newest_release() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100" \
    | tr ',' '\n' \
    | awk '
        /"tag_name":/ { t = $0; sub(/.*"tag_name": *"/, "", t); sub(/".*/, "", t) }
        /"prerelease": *false/ && index(t, "v") == 1 { print t }' \
    | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1 | sed 's/^/v/'
}

if [ -n "${PCMD_BASE_URL:-}" ]; then
  # Explicit mirror / local artifact dir. No version resolution needed.
  BASE="${PCMD_BASE_URL%/}"
  [ "$VERSION" = "latest" ] && VERSION="local"
else
  if [ "$VERSION" = "latest" ]; then
    info "Resolving latest release of ${REPO}..."
    VERSION="$(newest_release)"
    [ -n "$VERSION" ] || err "could not determine the latest release of ${REPO}"
  fi
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# Asked while the old binary still runs the service: 0 running, 2 stopped.
SERVICE=""
if [ -n "$EXISTING" ]; then
  CURRENT="$("$EXISTING" --version 2>/dev/null | awk '{print "v" $2}')"
  if [ "$CURRENT" = "$VERSION" ]; then
    info "${BINARY} ${VERSION} is already installed at ${EXISTING}."
    exit 0
  fi
  rc=0; "$EXISTING" status --json >/dev/null 2>&1 || rc=$?
  case $rc in
    0) SERVICE=running ;;
    2) SERVICE=stopped ;;
  esac
  info "Updating ${BINARY} ${CURRENT:-(unknown version)} to ${VERSION} (${OS}/${ARCH})"
else
  info "Installing ${BINARY} ${VERSION} (${OS}/${ARCH})"
fi

# --- download into a temp dir ----------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

info "Downloading ${ARCHIVE}..."
fetch "${BASE}/${ARCHIVE}"      "${TMP}/${ARCHIVE}"      || err "failed to download ${ARCHIVE}. Is ${VERSION} published for ${OS}/${ARCH}?"
fetch "${BASE}/checksums.txt"   "${TMP}/checksums.txt"   || err "failed to download checksums.txt"

# --- verify checksum (mandatory) -------------------------------------------
info "Verifying checksum..."
expected="$(grep " ${ARCHIVE}\$" "${TMP}/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || err "no checksum listed for ${ARCHIVE}"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')"
else
  err "no sha256 tool found (need sha256sum or shasum)"
fi
[ "$expected" = "$actual" ] || err "checksum mismatch for ${ARCHIVE} (expected ${expected}, got ${actual})"
info "Checksum OK."

# --- verify cosign signature (best-effort) ---------------------------------
if command -v cosign >/dev/null 2>&1; then
  info "Verifying cosign signature..."
  if fetch "${BASE}/checksums.txt.sigstore.json" "${TMP}/checksums.txt.sigstore.json" 2>/dev/null; then
    if cosign verify-blob \
        --bundle "${TMP}/checksums.txt.sigstore.json" \
        --certificate-identity-regexp "$COSIGN_IDENTITY" \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        "${TMP}/checksums.txt" >/dev/null 2>&1; then
      info "Signature OK (keyless, transparency-logged)."
    else
      err "cosign signature verification FAILED, aborting install."
    fi
  else
    warn "no cosign signature published for this release; skipping."
  fi
else
  info "cosign not installed; skipping signature check (checksum already verified)."
  info "For the strongest guarantee, install cosign and re-run."
fi

# --- extract ---------------------------------------------------------------
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"
[ -f "${TMP}/${BINARY}" ] || err "archive did not contain ${BINARY}"
chmod +x "${TMP}/${BINARY}"

# --- choose install dir ----------------------------------------------------
if [ -n "${PCMD_INSTALL_DIR:-}" ]; then
  DEST="$PCMD_INSTALL_DIR"
  mkdir -p "$DEST"
elif [ -n "$EXISTING" ]; then
  DEST="$(dirname "$EXISTING")"
  if [ ! -w "$DEST" ]; then
    command -v sudo >/dev/null 2>&1 || err "${DEST} is not writable and sudo is not available"
    SUDO=sudo
  fi
elif [ -w /usr/local/bin ] 2>/dev/null; then
  DEST=/usr/local/bin
elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
  DEST=/usr/local/bin
  SUDO=sudo
else
  DEST="${HOME}/.local/bin"
  mkdir -p "$DEST"
fi

put() { # put <file>: install it as ${DEST}/${BINARY}
  if [ "${SUDO:-}" = "sudo" ]; then
    sudo install -m 0755 "$1" "${DEST}/${BINARY}"
  else
    install -m 0755 "$1" "${DEST}/${BINARY}"
  fi
}

[ -n "$EXISTING" ] && cp "$EXISTING" "${TMP}/${BINARY}.previous"
info "Installing to ${DEST}/${BINARY}..."
put "${TMP}/${BINARY}"

# --- restart a running service ---------------------------------------------
# pcmd restart exits 4 when the new server fails its health check; anything
# else non-zero means the restart itself could not run, which a rollback would
# not fix.
if [ "$SERVICE" = running ]; then
  info "Restarting the service..."
  rc=0; "${DEST}/${BINARY}" restart || rc=$?
  case $rc in
    0) ;;
    4) warn "${VERSION} failed its health check; putting the previous version back."
       put "${TMP}/${BINARY}.previous"
       "${DEST}/${BINARY}" restart \
         && err "update to ${VERSION} failed; the previous version is running again (see: ${BINARY} logs)"
       err "update to ${VERSION} failed and the previous version did not come back up either; see https://github.com/${REPO}/blob/main/docs/deployment.md#rolling-back-an-update" ;;
    *) err "${BINARY} ${VERSION} is installed but the service could not be restarted; run: ${BINARY} restart" ;;
  esac
fi

# --- done ------------------------------------------------------------------
printf '\n\033[32m✓\033[0m %s %s installed to %s/%s\n\n' "$BINARY" "$VERSION" "$DEST" "$BINARY"
case "$SERVICE" in
  running) info "The service is running ${VERSION}." ;;
  stopped) info "The service is stopped; start it with: ${BINARY} start" ;;
  *) case ":${PATH}:" in
       *":${DEST}:"*) info "Run: ${BINARY}" ;;
       *) warn "${DEST} is not on your PATH."
          info "Add it:  export PATH=\"${DEST}:\$PATH\""
          info "Then run: ${BINARY}" ;;
     esac ;;
esac
