// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include <limits>
#include <stdint.h>
#include <string>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

static const CAmount COIN = 1000000;
static const CAmount CENT = 10000;

static const CAmount MIN_TX_FEE_PREV7 = CENT;
static const CAmount MIN_TX_FEE = CENT / 10;
static const CAmount PERKB_TX_FEE = CENT;
static const CAmount MIN_TXOUT_AMOUNT = CENT;
static const CAmount MAX_MINT_PROOF_OF_WORK = 9999 * COIN;
static const CAmount MAX_MINT_PROOF_OF_WORK_V10 = 50 * COIN;
static const std::string CURRENCY_UNIT = "PPC";

inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= std::numeric_limits<CAmount>::max()); }

#endif //  BITCOIN_AMOUNT_H
