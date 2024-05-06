// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fees.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <string>

namespace node {
struct NodeContext;
}

using node::NodeContext;
class ChainstateManager;

static RPCHelpMan estimatesmartfee()
{
    return RPCHelpMan{"estimatesmartfee",
        "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
        "confirmation within conf_target blocks if possible and return the number of blocks\n"
        "for which the estimate is valid. Uses virtual transaction size as defined\n"
        "in BIP 141 (witness data is discounted).\n",
        {
            {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"conservative"}, "The fee estimate mode.\n"
            "Whether to return a more conservative estimate which also satisfies\n"
            "a longer history. A conservative estimate potentially returns a\n"
            "higher feerate and is more likely to be sufficient for the desired\n"
            "target, but is not as responsive to short term drops in the\n"
            "prevailing fee market. Must be one of (case insensitive):\n"
             "\""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "feerate", /*optional=*/true, "estimate fee rate in " + CURRENCY_UNIT + "/kvB (only present if no errors were encountered)"},
                {RPCResult::Type::ARR, "errors", /*optional=*/true, "Errors encountered during processing (if there are any)",
                    {
                        {RPCResult::Type::STR, "", "error"},
                    }},
                {RPCResult::Type::NUM, "blocks", "block number where estimate was found\n"
                "The request target will be clamped between 2 and the highest target\n"
                "fee estimation is able to return based on how long it has been running.\n"
                "An error is returned if not enough transactions and blocks\n"
                "have been observed to make an estimate for any number of blocks."},
        }},
        RPCExamples{
            HelpExampleCli("estimatesmartfee", "6") +
            HelpExampleRpc("estimatesmartfee", "6")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            //RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
            //RPCTypeCheckArgument(request.params[0], UniValue::VNUM);

            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            UniValue result(UniValue::VOBJ);
            result.pushKV("feerate", 0.01);
            LOCK(cs_main);
            result.pushKV("blocks", chainman.ActiveChain().Height());
            return result;
        },
    };
}

void RegisterFeeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"util", &estimatesmartfee},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
