#!/bin/sh
# traced без установки:
#   curl -sL traced.netkitty.dev | sh -s -- 1.1.1.1
#   wget -qO- traced.netkitty.dev | sh -s -- whois example.com
# бинарник качается во временную папку, запускается и удаляется. TRACED_VERSION=v1.0.1 — конкретная версия.
set -e
REPO="PalMeany/traced-cli"
VER="${TRACED_VERSION:-latest}"

case "$(uname -s)" in
  Linux) os=linux ;; Darwin) os=darwin ;; FreeBSD) os=freebsd ;;
  *) echo "traced: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; armv7l|armv7*) arch=arm ;; i386|i686) arch=386 ;;
  *) echo "traced: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

name="traced-$os-$arch"
if [ "$VER" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
else base="https://github.com/$REPO/releases/download/$VER"; fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t traced)
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else echo "traced: curl or wget is required" >&2; exit 1; fi
}

fetch "$base/$name" "$tmp/traced" || { echo "traced: failed to download $name" >&2; exit 1; }
if fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
  want=$(grep " $name\$" "$tmp/SHA256SUMS" | awk '{print $1}')
  if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/traced" | awk '{print $1}')
  else got=$(shasum -a 256 "$tmp/traced" | awk '{print $1}'); fi
  if [ -n "$want" ] && [ "$want" != "$got" ]; then echo "traced: checksum mismatch" >&2; exit 1; fi
fi
chmod +x "$tmp/traced"

# traceroute шлёт сырые пакеты: на linux без root/CAP_NET_RAW не заработает
if [ "$os" = linux ] && [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1; then
  case "$1" in whois|asn|as|rep|reputation|feeds|version|history|diff|"") "$tmp/traced" "$@" ;; *) sudo "$tmp/traced" "$@" ;; esac
else
  "$tmp/traced" "$@"
fi
