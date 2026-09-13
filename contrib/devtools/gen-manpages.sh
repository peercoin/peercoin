#!/usr/bin/env bash
# Copyright (c) 2016-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR/build}

BINDIR=${BINDIR:-$BUILDDIR/bin}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

BITCOIND=${BITCOIND:-$BINDIR/peercoind}
BITCOINCLI=${BITCOINCLI:-$BINDIR/peercoin-cli}
BITCOINTX=${BITCOINTX:-$BINDIR/peercoin-tx}
WALLET_TOOL=${WALLET_TOOL:-$BINDIR/peercoin-wallet}
BITCOINUTIL=${BITCOINUTIL:-$BINDIR/peercoin-util}
BITCOINQT=${BITCOINQT:-$BINDIR/peercoin-qt}

cmds=("$BITCOIND" "$BITCOINCLI" "$BITCOINTX" "$WALLET_TOOL" "$BITCOINUTIL" "$BITCOINQT")

for cmd in "${cmds[@]}"; do
  [ -x "$cmd" ] || { echo "$cmd not found or not executable." >&2; exit 1; }
done

# Don't allow man pages to be generated for binaries built from a dirty tree
DIRTY=()
for cmd in "${cmds[@]}"; do
  VERSION_OUTPUT=$("$cmd" --version)
  if [[ $VERSION_OUTPUT == *"dirty"* ]]; then
    DIRTY+=("$cmd")
  fi
done
if [ ${#DIRTY[@]} -gt 0 ]; then
  echo "WARNING: the following binaries were built from a dirty tree:" >&2
  printf '  %s\n' "${DIRTY[@]}" >&2
  echo "man pages generated from dirty binaries should NOT be committed." >&2
  echo "To properly generate man pages, please commit your changes to the above binaries, rebuild them, then run this script again." >&2
fi

VERSION=$("$BITCOINCLI" --version | head -n1 | sed -n 's/.*\(v[0-9][0-9.]*\).*/\1/p')
if [ -z "$VERSION" ]; then
  echo "Could not determine version from $BITCOINCLI --version" >&2
  exit 1
fi

footer=$(mktemp "${TMPDIR:-/tmp}/peercoin-footer.XXXXXX.h2m")
trap 'rm -f "$footer"' EXIT

printf '[COPYRIGHT]\n' > "$footer"
"$BITCOIND" --version | sed -n '1!p' >> "$footer"

for cmd in "${cmds[@]}"; do
  cmdname="${cmd##*/}"
  help2man -N --version-string="$VERSION" --include="$footer" -o "${MANDIR}/${cmdname}.1" "$cmd"
done
