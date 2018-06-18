// Copyright (c) 2012 The Bitcoin developers
// Copyright (c) 2012-2018 The Peercoin developers
// Copyright (c) 2018      The Sprouts developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include "clientversion.h"
#include <string>

//
// client versioning
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;

static const int SPROUTS_VERSION =
                           1000000 * SPROUTS_VERSION_MAJOR
                         +   10000 * SPROUTS_VERSION_MINOR
                         +     100 * SPROUTS_VERSION_REVISION
                         +       1 * SPROUTS_VERSION_BUILD;

//
// network protocol versioning
//

static const int PROTOCOL_VERSION = 70002;

// earlier versions not supported as of Feb 2012, and are disconnected
// NOTE: as of bitcoin v0.6 message serialization (vSend, vRecv) still
// uses MIN_PROTO_VERSION(209), where message format uses PROTOCOL_VERSION
static const int MIN_PROTO_VERSION = 209;
static const int MIN_PROTO_VERSION_V06 = 70002; // for kernel version v0.6

// nTime field added to CAddress, starting with this version;
// if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

// only request blocks from nodes outside this range of versions
static const int NOBLKS_VERSION_START = 32000;
static const int NOBLKS_VERSION_END = 32400;
static const int NOBLKS_VERSION_END_V06 = 70001; // for kernel version v0.6

// BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

// "mempool" command, enhanced "getdata" behavior starts with this version:
static const int MEMPOOL_GD_VERSION = 60002;

#endif
