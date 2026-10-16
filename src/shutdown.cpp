// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shutdown.h>
#include <cstdio>

#if defined(HAVE_CONFIG_H)
#endif

#include <logging.h>
#include <node/interface_ui.h>
#include <util/tokenpipe.h>

#include <assert.h>
#include <atomic>
#ifdef WIN32
#include <condition_variable>
#endif

#include <util/signalinterrupt.h>

//! peercoin: unified v31 shutdown interrupt — signal handlers, rpc stop and
//! WaitForShutdown all rendezvous through this single SignalInterrupt.
util::SignalInterrupt g_shutdown_interrupt;

bool AbortNode(const std::string& strMessage, bilingual_str user_message)
{
    LogPrintf("*** %s\n", strMessage);
    if (user_message.empty()) {
        user_message = _("A fatal internal error occurred, see debug.log for details");
    }
    InitError(user_message);
    StartShutdown();
    return false;
}

bool InitShutdownState()
{
    return true;
}

void StartShutdown()
{
    (void)g_shutdown_interrupt();
}

void AbortShutdown()
{
    (void)g_shutdown_interrupt.reset();
}

bool ShutdownRequested()
{
    return bool{g_shutdown_interrupt};
}

void WaitForShutdown()
{
    (void)g_shutdown_interrupt.wait();
}
