# Release notes now being edited on https://github.com/bitcoin-core/bitcoin-devwiki/wiki/22.0-Release-Notes-draft

*After branching off for a major version release of Bitcoin Core, use this
template to create the initial release notes draft.*

*The release notes draft is a temporary file that can be added to by anyone. See
[/doc/developer-notes.md#release-notes](/doc/developer-notes.md#release-notes)
for the process.*

*Create the draft, named* "*version* Release Notes Draft"
*(e.g. "22.0 Release Notes Draft"), as a collaborative wiki in:*

https://github.com/bitcoin-core/bitcoin-devwiki/wiki/

*Before the final release, move the notes back to this git repository.*

*version* Release Notes Draft
===============================

Bitcoin Core version *version* is now available from:

  <https://bitcoincore.org/bin/bitcoin-core-*version*/>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from a version of Bitcoin Core that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Core are generally supported.

Compatibility
==============

Bitcoin Core is supported and extensively tested on operating systems
using the Linux kernel, macOS 10.15+, and Windows 7 and newer.  Bitcoin
Core should also work on most other Unix-like systems but is not as
frequently tested on them.  It is not recommended to use Bitcoin Core on
unsupported systems.

Notable changes
===============

P2P and network changes
-----------------------

- A bitcoind node will no longer rumour addresses to inbound peers by default.
  They will become eligible for address gossip after sending an ADDR, ADDRV2,
  or GETADDR message. (#21528)

Rescan startup parameter removed
--------------------------------

The `-rescan` startup parameter has been removed. Wallets which require
rescanning due to corruption will still be rescanned on startup.
Otherwise, please use the `rescanblockchain` RPC to trigger a rescan. (#23123)

- The size of the set of transactions that peers have announced and we consider
  for requests has been reduced from 100000 to 5000 (per peer), and further
  announcements will be ignored when that limit is reached. If you need to dump
  (very) large batches of transactions, exceptions can be made for trusted
  peers using the "relay" network permission. For localhost for example it can
  be enabled using the command line option `-whitelist=relay@127.0.0.1`.
  (#19988)

- The Tor onion service that is automatically created by setting the
  `-listenonion` configuration parameter will now be created as a Tor v3 service
  instead of Tor v2. The private key that was used for Tor v2 (if any) will be
  left untouched in the `onion_private_key` file in the data directory (see
  `-datadir`) and can be removed if not needed. Bitcoin Core will no longer
  attempt to read it. The private key for the Tor v3 service will be saved in a
  file named `onion_v3_private_key`. To use the deprecated Tor v2 service (not
  recommended), then `onion_private_key` can be copied over
  `onion_v3_private_key`, e.g.
  `cp -f onion_private_key onion_v3_private_key`. (#19954)

Updated RPCs
------------

- Due to [BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
  being implemented, behavior for all RPCs that accept addresses is changed when
  a native witness version 1 (or higher) is passed. These now require a Bech32m
  encoding instead of a Bech32 one, and Bech32m encoding will be used for such
  addresses in RPC output as well. No version 1 addresses should be created
  for mainnet until consensus rules are adopted that give them meaning
  (e.g. through [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)).
  Once that happens, Bech32m is expected to be used for them, so this shouldn't
  affect any production systems, but may be observed on other networks where such
  addresses already have meaning (like signet). (#20861)

- The `getpeerinfo` RPC returns two new boolean fields, `bip152_hb_to` and
  `bip152_hb_from`, that respectively indicate whether we selected a peer to be
  in compact blocks high-bandwidth mode or whether a peer selected us as a
  compact blocks high-bandwidth peer. High-bandwidth peers send new block
  announcements via a `cmpctblock` message rather than the usual inv/headers
  announcements. See BIP 152 for more details. (#19776)

- `getpeerinfo` no longer returns the following fields: `addnode`, `banscore`,
  and `whitelisted`, which were previously deprecated in 0.21. Instead of
  `addnode`, the `connection_type` field returns manual. Instead of
  `whitelisted`, the `permissions` field indicates if the peer has special
  privileges. The `banscore` field has simply been removed. (#20755)

- The `validateaddress` RPC now returns an `error_locations` array for invalid
  addresses, with the indices of invalid character locations in the address (if
  known). For example, this will attempt to locate up to two Bech32 errors, and
  return their locations if successful. Success and correctness are only guaranteed
  if fewer than two substitution errors have been made.
  The error message returned in the `error` field now also returns more specific
  errors when decoding fails. (#16807)

- The `-deprecatedrpc=addresses` configuration option has been removed.  RPCs
  `gettxout`, `getrawtransaction`, `decoderawtransaction`, `decodescript`,
  `gettransaction verbose=true` and REST endpoints `/rest/tx`, `/rest/getutxos`,
  `/rest/block` no longer return the `addresses` and `reqSigs` fields, which
  were previously deprecated in 22.0. (#22650)
- The `getblock` RPC command now supports verbosity level 3 containing transaction inputs'
  `prevout` information.  The existing `/rest/block/` REST endpoint is modified to contain
  this information too. Every `vin` field will contain an additional `prevout` subfield
  describing the spent output. `prevout` contains the following keys:
  - `generated` - true if the spent coins was a coinbase.
  - `height`
  - `value`
  - `scriptPubKey`

- The top-level fee fields `fee`, `modifiedfee`, `ancestorfees` and `descendantfees`
  returned by RPCs `getmempoolentry`,`getrawmempool(verbose=true)`,
  `getmempoolancestors(verbose=true)` and `getmempooldescendants(verbose=true)`
  are deprecated and will be removed in the next major version (use
  `-deprecated=fees` if needed in this version). The same fee fields can be accessed
  through the `fees` object in the result. WARNING: deprecated
  fields `ancestorfees` and `descendantfees` are denominated in sats, whereas all
  fields in the `fees` object are denominated in BTC. (#22689)

- Both `createmultisig` and `addmultisigaddress` now include a `warnings`
  field, which will show a warning if a non-legacy address type is requested
  when using uncompressed public keys. (#23113)

New RPCs
--------

- Information on soft fork status has been moved from `getblockchaininfo`
  to the new `getdeploymentinfo` RPC which allows querying soft fork status at any
  block, rather than just at the chain tip. Inclusion of soft fork
  status in `getblockchaininfo` can currently be restored using the
  configuration `-deprecatedrpc=softforks`, but this will be removed in
  a future release. Note that in either case, the `status` field
  now reflects the status of the current block rather than the next
  block. (#23508)

Build System
------------

Files
-----

* On startup, the list of banned hosts and networks (via `setban` RPC) in
  `banlist.dat` is ignored and only `banlist.json` is considered. Bitcoin Core
  version 22.x is the only version that can read `banlist.dat` and also write
  it to `banlist.json`. If `banlist.json` already exists, version 22.x will not
  try to translate the `banlist.dat` into json. After an upgrade, `listbanned`
  can be used to double check the parsed entries. (#22570)

New settings
------------

- The `-natpmp` option has been added to use NAT-PMP to map the listening port.
  If both UPnP and NAT-PMP are enabled, a successful allocation from UPnP
  prevails over one from NAT-PMP. (#18077)

Updated settings
----------------

- In previous releases, the meaning of the command line option
  `-persistmempool` (without a value provided) incorrectly disabled mempool
  persistence.  `-persistmempool` is now treated like other boolean options to
  mean `-persistmempool=1`. Passing `-persistmempool=0`, `-persistmempool=1`
  and `-nopersistmempool` is unaffected. (#23061)

- `-maxuploadtarget` now allows human readable byte units [k|K|m|M|g|G|t|T].
  E.g. `-maxuploadtarget=500g`. No whitespace, +- or fractions allowed.
  Default is `M` if no suffix provided. (#23249)

- If `-proxy=` is given together with `-noonion` then the provided proxy will
  not be set as a proxy for reaching the Tor network. So it will not be
  possible to open manual connections to the Tor network for example with the
  `addnode` RPC. To mimic the old behavior use `-proxy=` together with
  `-onlynet=` listing all relevant networks except `onion`. (#22834)

- Passing an invalid `-rpcauth` argument now cause bitcoind to fail to start.  (#20461)

Tools and Utilities
-------------------

- Update `-getinfo` to return data in a user-friendly format that also reduces vertical space. (#21832)

- CLI `-addrinfo` now returns a single field for the number of `onion` addresses
  known to the node instead of separate `torv2` and `torv3` fields, as support
  for Tor V2 addresses was removed from Bitcoin Core in 22.0. (#22544)

- The `startupnotify` option is used to specify a command to
  execute when Bitcoin Core has finished with its startup
  sequence. (#15367)

- A new `-rpcwaittimeout` argument to `bitcoin-cli` sets the timeout
  in seconds to use with `-rpcwait`. If the timeout expires,
  `bitcoin-cli` will report a failure. (#21056)

Wallet
------

- `upgradewallet` will now automatically flush the keypool if upgrading
  from a non-HD wallet to an HD wallet, to immediately start using the
  newly-generated HD keys. (#23093)

- a new RPC `newkeypool` has been added, which will flush (entirely
  clear and refill) the keypool. (#23093)

- `listunspent` now includes `ancestorcount`, `ancestorsize`, and
  `ancestorfees` for each transaction output that is still in the mempool.
  (#12677)

- `lockunspent` now optionally takes a third parameter, `persistent`, which
  causes the lock to be written persistently to the wallet database. This
  allows UTXOs to remain locked even after node restarts or crashes. (#23065)

- `receivedby` RPCs now include coinbase transactions. Previously, the
  following wallet RPCs excluded coinbase transactions: `getreceivedbyaddress`,
  `getreceivedbylabel`, `listreceivedbyaddress`, `listreceivedbylabel`. This
  release changes this behaviour and returns results accounting for received
  coins from coinbase outputs. The previous behaviour can be restored using the
  configuration `-deprecatedrpc=exclude_coinbase`, but may be removed in a
  future release. (#14707)

- A new option in the same `receivedby` RPCs, `include_immature_coinbase`
  (default=`false`), determines whether to account for immature coinbase
  transactions. Immature coinbase transactions are coinbase transactions that
  have 100 or fewer confirmations, and are not spendable. (#14707)

- The `upgradewallet` RPC replaces the `-upgradewallet` command line option.
  (#15761)
- The `settxfee` RPC will fail if the fee was set higher than the `-maxtxfee`
  command line setting. The wallet will already fail to create transactions
  with fees higher than `-maxtxfee`. (#18467)

- The `bumpfee` RPC is not available with wallets that have private keys
  disabled. `psbtbumpfee` can be used instead. (#20891)

- The `fundrawtransaction`, `send` and `walletcreatefundedpsbt` RPCs now support an `include_unsafe` option
  that when `true` allows using unsafe inputs to fund the transaction.
  Note that the resulting transaction may become invalid if one of the unsafe inputs disappears.
  If that happens, the transaction must be funded with different inputs and republished. (#21359)

- We now support up to 20 keys in `multi()` and `sortedmulti()` descriptors
  under `wsh()`. (#20867)

GUI changes
-----------

- UTXOs which are locked via the GUI are now stored persistently in the
  wallet database, so are not lost on node shutdown or crash. (#23065)

- The Bech32 checkbox has been replaced with a dropdown for all address types, including the new Bech32m (BIP-350) standard for Taproot enabled wallets.

Low-level changes
=================

RPC
---

- `getblockchaininfo` now returns a new `time` field, that provides the chain tip time. (#22407)

- The RPC server can process a limited number of simultaneous RPC requests.
  Previously, if this limit was exceeded, the RPC server would respond with
  [status code 500 (`HTTP_INTERNAL_SERVER_ERROR`)](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_server_errors).
  Now it returns status code 503 (`HTTP_SERVICE_UNAVAILABLE`). (#18335)

- `getblockchaininfo` now returns a new `time` field, that provides the chain tip time. (#22407)

- The `sendrawtransaction` error code for exceeding `maxfeerate` has been changed from
  `-26` to `-25`. The error string has been changed from "absurdly-high-fee" to
  "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)." The
  `testmempoolaccept` RPC returns `max-fee-exceeded` rather than `absurdly-high-fee`
  as the `reject-reason`. (#19339)

- To make wallet and rawtransaction RPCs more consistent, the error message for
  exceeding maximum feerate has been changed to "Fee exceeds maximum configured by user
  (e.g. -maxtxfee, maxfeerate)." (#19339)

Tests
-----

- For the `regtest` network the activation heights of several softforks were
  set to block height 1. They can be changed by the runtime setting
  `-testactivationheight=name@height`. (#22818)

Credits
=======

Thanks to everyone who directly contributed to this release:


As well as to everyone that helped with translations on
[Transifex](https://www.transifex.com/bitcoin/bitcoin/).
