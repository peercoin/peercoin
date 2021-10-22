#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
  echo "$0: assuming arguments for peercoind"

  set -- peercoind "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "peercoind" ]; then
  mkdir -p "$PEERCOIN_DATA"
  chmod 700 "$PEERCOIN_DATA"
  chown -R peercoin "$PEERCOIN_DATA"

  echo "$0: setting data directory to $PEERCOIN_DATA"

  set -- "$@" -datadir="$PEERCOIN_DATA"
fi

if [ "$1" = "peercoind" ] || [ "$1" = "peercoin-cli" ] || [ "$1" = "peercoin-tx" ] || [ "$1" = "peercoin-wallet" ]; then
  echo
  exec gosu peercoin "$@"
fi

echo
exec "$@"
