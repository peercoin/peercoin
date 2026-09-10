// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <timedata.h>

#include <util/time.h>

// peercoin: see timedata.h; this mirrors net_processing's median outbound
// time offset for legacy PPC-era callers of GetAdjustedTime().
std::atomic<int64_t> g_time_offset_seconds{0};

int64_t GetTimeOffset()
{
    return g_time_offset_seconds.load();
}

int64_t GetAdjustedTime()
{
    return GetTime() + GetTimeOffset();
}
