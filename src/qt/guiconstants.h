// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUICONSTANTS_H
#define BITCOIN_QT_GUICONSTANTS_H

#include <chrono>
#include <cstdint>

using namespace std::chrono_literals;

/* A delay between model updates */
static constexpr auto MODEL_UPDATE_DELAY{1000ms};

/* A delay between shutdown pollings */
static constexpr auto SHUTDOWN_POLLING_DELAY{200ms};

/* AskPassphraseDialog -- Maximum passphrase length */
static const int MAX_PASSPHRASE_SIZE = 1024;

/* BitcoinGUI -- Size of icons in status bar */
static const int STATUSBAR_ICONSIZE = 16;

static const bool DEFAULT_SPLASHSCREEN = true;

/* Invalid field background style */
#define STYLE_INVALID "background:#FF8080"

/* Transaction list -- unconfirmed transaction */
#define COLOR_UNCONFIRMED QColor(140, 140, 140)
/* Transaction list -- negative amount */
#define COLOR_NEGATIVE QColor(255, 58, 66)
/* Table List -- negative amount */
#define COLOR_NEGATIVE_TABLE QColor(255, 58, 66)
/* Transaction list -- positive amount */
#define COLOR_POSITIVE QColor(60, 176, 84)
/* Transaction list -- bare address (without label) */
#define COLOR_BAREADDRESS QColor(121, 121, 121)
/* Transaction list -- TX status decoration - danger, tx needs attention */
#define COLOR_TX_STATUS_DANGER QColor(200, 100, 100)
/* Transaction list -- TX status decoration - default color */
#define COLOR_BLACK QColor(0, 0, 0)

/* Tooltips longer than this (in characters) are converted into rich text,
   so that they can be word-wrapped.
 */
static const int TOOLTIP_WRAP_THRESHOLD = 80;

/* Number of frames in spinner animation */
#define SPINNER_FRAMES 36

#define QAPP_ORG_NAME "Peercoin"
#define QAPP_ORG_DOMAIN "peercoin.net"
#define QAPP_APP_NAME_DEFAULT "Peercoin-Qt"
#define QAPP_APP_NAME_TESTNET "Peercoin-Qt-testnet"
#define QAPP_APP_NAME_REGTEST "Peercoin-Qt-regtest"
#define QAPP_APP_NAME_SIGNET "Peercoin-Qt-signet"

/* Colors for minting tab for each coin age group */
#define COLOR_MINT_YOUNG QColor(255, 224, 226)
#define COLOR_MINT_MATURE QColor(204, 255, 207)
#define COLOR_MINT_OLD QColor(111, 252, 141)

/* One gigabyte (GB) in bytes */
static constexpr uint64_t GB_BYTES{1000000000};

#endif // BITCOIN_QT_GUICONSTANTS_H
