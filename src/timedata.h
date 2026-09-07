// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TIMEDATA_H
#define BITCOIN_TIMEDATA_H

#include <atomic>
#include <cstdint>

/**
 * peercoin: compatibility shim for the pre-v28 timedata API. Upstream moved
 * time-offset tracking into node/timeoffsets.h (a net_processing-owned
 * instance); this shim exposes the legacy free functions backed by the
 * median offset mirrored there, so PPC-era code keeps working.
 */
extern std::atomic<int64_t> g_time_offset_seconds;

/** The network-adjusted time as seconds since the epoch. */
int64_t GetAdjustedTime();

/** The network-adjusted time offset, in seconds. */
int64_t GetTimeOffset();

#endif // BITCOIN_TIMEDATA_H
