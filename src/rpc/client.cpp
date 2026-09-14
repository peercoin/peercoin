// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <tinyformat.h>
#include <util/system.h>

#include <set>
#include <stdint.h>
#include <string>
#include <string_view>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

// clang-format off
/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "addconnection", 2, "v2transport" },
    { "addnode", 2, "v2transport" },
    { "addpeeraddress", 1, "port" },
    { "addpeeraddress", 2, "tried" },
    { "bumpfee", 1, "conf_target" },
    { "bumpfee", 1, "fee_rate" },
    { "bumpfee", 1, "options" },
    { "bumpfee", 1, "original_change_index" },
    { "bumpfee", 1, "outputs" },
    { "bumpfee", 1, "replaceable" },
    { "bumpmocktime", 0, "n" },
    { "combinepsbt", 0, "txs" },
    { "combinerawtransaction", 0, "txs" },
    { "converttopsbt", 1, "permitsigdata" },
    { "converttopsbt", 2, "iswitness" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "createpsbt", 0, "inputs" },
    { "createpsbt", 1, "outputs" },
    { "createpsbt", 2, "locktime" },
    { "createpsbt", 3, "replaceable" },
    { "createpsbt", 4, "version" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "createrawtransaction", 3, "replaceable" },
    { "createrawtransaction", 4, "version" },
    { "createwallet", 1, "disable_private_keys" },
    { "createwallet", 2, "blank" },
    { "createwallet", 4, "avoid_reuse" },
    { "createwallet", 5, "descriptors" },
    { "createwallet", 6, "load_on_startup" },
    { "createwallet", 7, "external_signer" },
    { "createwalletdescriptor", 1, "internal" },
    { "createwalletdescriptor", 1, "options" },
    { "decoderawtransaction", 1, "iswitness" },
    { "deriveaddresses", 1, "range" },
    { "descriptorprocesspsbt", 1, "descriptors" },
    { "descriptorprocesspsbt", 3, "bip32derivs" },
    { "descriptorprocesspsbt", 4, "finalize" },
    { "disconnectnode", 1, "nodeid" },
    { "estimatesmartfee", 0, "conf_target" },
    { "finalizepsbt", 1, "extract" },
    { "fundrawtransaction", 1, "add_inputs" },
    { "fundrawtransaction", 1, "changePosition" },
    { "fundrawtransaction", 1, "conf_target" },
    { "fundrawtransaction", 1, "feeRate" },
    { "fundrawtransaction", 1, "fee_rate" },
    { "fundrawtransaction", 1, "includeWatching" },
    { "fundrawtransaction", 1, "include_unsafe" },
    { "fundrawtransaction", 1, "input_weights" },
    { "fundrawtransaction", 1, "lockUnspents" },
    { "fundrawtransaction", 1, "max_tx_weight" },
    { "fundrawtransaction", 1, "maxconf" },
    { "fundrawtransaction", 1, "minconf" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 1, "replaceable" },
    { "fundrawtransaction", 1, "solving_data" },
    { "fundrawtransaction", 1, "subtractFeeFromOutputs" },
    { "fundrawtransaction", 2, "iswitness" },
    { "generateblock", 1, "transactions" },
    { "generateblock", 2, "submit" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "generatetodescriptor", 0, "num_blocks" },
    { "generatetodescriptor", 2, "maxtries" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getbalance", 3, "avoid_reuse" },
    { "getblock", 1, "verbose" },
    { "getblock", 1, "verbosity" },
    { "getblockfrompeer", 1, "peer_id" },
    { "getblockhash", 0, "height" },
    { "getblockheader", 1, "verbose" },
    { "getblockstats", 0, "hash_or_height" },
    { "getblockstats", 1, "stats" },
    { "getblocktemplate", 0, "template_request" },
    { "getchaintxstats", 0, "nblocks" },
    { "gethdkeys", 0, "active_only" },
    { "gethdkeys", 0, "options" },
    { "gethdkeys", 0, "private" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "getnodeaddresses", 0, "count" },
    { "getorphantxs", 0, "verbosity" },
    { "getrawmempool", 0, "verbose" },
    { "getrawmempool", 1, "mempool_sequence" },
    { "getrawtransaction", 1, "verbose" },
    { "getrawtransaction", 1, "verbosity" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaddress", 2, "include_immature_coinbase" },
    { "getreceivedbylabel", 1, "minconf" },
    { "getreceivedbylabel", 2, "include_immature_coinbase" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettransaction", 2, "verbose" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "gettxoutsetinfo", 1, "hash_or_height" },
    { "gettxoutsetinfo", 2, "use_index" },
    { "gettxspendingprevout", 0, "outputs" },
    { "gettxspendingprevout", 1, "mempool_only" },
    { "gettxspendingprevout", 1, "options" },
    { "gettxspendingprevout", 1, "return_spending_tx" },
    { "importcoinstake", 1, "timestamp" },
    { "importdescriptors", 0, "requests" },
    { "importmempool", 1, "apply_fee_delta_priority" },
    { "importmempool", 1, "apply_unbroadcast_set" },
    { "importmempool", 1, "options" },
    { "importmempool", 1, "use_current_time" },
    { "joinpsbts", 0, "txs" },
    { "keypoolrefill", 0, "newsize" },
    { "listdescriptors", 0, "private" },
    { "listminting", 0, "count" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaddress", 4, "include_immature_coinbase" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "listreceivedbylabel", 3, "include_immature_coinbase" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "listsinceblock", 4, "include_change" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "include_immature_coinbase" },
    { "listunspent", 4, "maximumAmount" },
    { "listunspent", 4, "maximumCount" },
    { "listunspent", 4, "minimumAmount" },
    { "listunspent", 4, "minimumSumAmount" },
    { "listunspent", 4, "query_options" },
    { "loadwallet", 1, "load_on_startup" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "lockunspent", 2, "persistent" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "mockscheduler", 0, "delta_time" },
    { "optimizeutxoset", 1, "amount" },
    { "optimizeutxoset", 2, "transmit" },
    { "psbtbumpfee", 1, "conf_target" },
    { "psbtbumpfee", 1, "fee_rate" },
    { "psbtbumpfee", 1, "options" },
    { "psbtbumpfee", 1, "original_change_index" },
    { "psbtbumpfee", 1, "outputs" },
    { "psbtbumpfee", 1, "replaceable" },
    { "rescanblockchain", 0, "start_height" },
    { "rescanblockchain", 1, "stop_height" },
    { "reservebalance", 0, "reserve" },
    { "reservebalance", 1, "amount" },
    { "restorewallet", 2, "load_on_startup" },
    { "scanblocks", 1, "scanobjects" },
    { "scanblocks", 2, "start_height" },
    { "scanblocks", 3, "stop_height" },
    { "scanblocks", 5, "options" },
    { "scantxoutset", 1, "scanobjects" },
    { "send", 0, "outputs" },
    { "send", 1, "conf_target" },
    { "send", 3, "fee_rate" },
    { "send", 4, "add_inputs" },
    { "send", 4, "add_to_wallet" },
    { "send", 4, "change_position" },
    { "send", 4, "conf_target" },
    { "send", 4, "fee_rate" },
    { "send", 4, "include_unsafe" },
    { "send", 4, "include_watching" },
    { "send", 4, "inputs" },
    { "send", 4, "lock_unspents" },
    { "send", 4, "locktime" },
    { "send", 4, "max_tx_weight" },
    { "send", 4, "maxconf" },
    { "send", 4, "minconf" },
    { "send", 4, "options" },
    { "send", 4, "psbt" },
    { "send", 4, "replaceable" },
    { "send", 4, "solving_data" },
    { "send", 4, "subtract_fee_from_outputs" },
    { "send", 5, "version" },
    { "sendall", 0, "recipients" },
    { "sendall", 1, "conf_target" },
    { "sendall", 3, "fee_rate" },
    { "sendall", 4, "add_to_wallet" },
    { "sendall", 4, "conf_target" },
    { "sendall", 4, "fee_rate" },
    { "sendall", 4, "include_watching" },
    { "sendall", 4, "inputs" },
    { "sendall", 4, "lock_unspents" },
    { "sendall", 4, "locktime" },
    { "sendall", 4, "maxconf" },
    { "sendall", 4, "minconf" },
    { "sendall", 4, "options" },
    { "sendall", 4, "psbt" },
    { "sendall", 4, "replaceable" },
    { "sendall", 4, "send_max" },
    { "sendall", 4, "solving_data" },
    { "sendall", 4, "version" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5, "replaceable" },
    { "sendmany", 6, "conf_target" },
    { "sendmany", 8, "fee_rate" },
    { "sendmany", 9, "verbose" },
    { "sendmsgtopeer", 0, "peer_id" },
    { "sendrawtransaction", 1, "maxfeerate" },
    { "sendrawtransaction", 2, "maxburnamount" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 5, "replaceable" },
    { "sendtoaddress", 6, "conf_target" },
    { "sendtoaddress", 8, "avoid_reuse" },
    { "sendtoaddress", 9, "fee_rate" },
    { "sendtoaddress", 10, "verbose" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setmocktime", 0, "timestamp" },
    { "setnetworkactive", 0, "state" },
    { "setwalletflag", 1, "value" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "simulaterawtransaction", 0, "rawtxs" },
    { "simulaterawtransaction", 1, "include_watchonly" },
    { "simulaterawtransaction", 1, "options" },
    { "stop", 0, "wait" },
    { "submitpackage", 0, "package" },
    { "submitpackage", 1, "maxfeerate" },
    { "submitpackage", 2, "maxburnamount" },
    { "testmempoolaccept", 0, "rawtxs" },
    { "testmempoolaccept", 1, "maxfeerate" },
    { "unloadwallet", 1, "load_on_startup" },
    { "utxoupdatepsbt", 1, "descriptors" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "waitforblock", 1, "timeout" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "walletcreatefundedpsbt", 0, "inputs" },
    { "walletcreatefundedpsbt", 1, "outputs" },
    { "walletcreatefundedpsbt", 2, "locktime" },
    { "walletcreatefundedpsbt", 3, "add_inputs" },
    { "walletcreatefundedpsbt", 3, "changePosition" },
    { "walletcreatefundedpsbt", 3, "conf_target" },
    { "walletcreatefundedpsbt", 3, "feeRate" },
    { "walletcreatefundedpsbt", 3, "fee_rate" },
    { "walletcreatefundedpsbt", 3, "includeWatching" },
    { "walletcreatefundedpsbt", 3, "include_unsafe" },
    { "walletcreatefundedpsbt", 3, "lockUnspents" },
    { "walletcreatefundedpsbt", 3, "max_tx_weight" },
    { "walletcreatefundedpsbt", 3, "maxconf" },
    { "walletcreatefundedpsbt", 3, "minconf" },
    { "walletcreatefundedpsbt", 3, "options" },
    { "walletcreatefundedpsbt", 3, "replaceable" },
    { "walletcreatefundedpsbt", 3, "solving_data" },
    { "walletcreatefundedpsbt", 3, "subtractFeeFromOutputs" },
    { "walletcreatefundedpsbt", 4, "bip32derivs" },
    { "walletcreatefundedpsbt", 5, "version" },
    { "walletpassphrase", 1, "timeout" },
    { "walletprocesspsbt", 1, "sign" },
    { "walletprocesspsbt", 3, "bip32derivs" },
    { "walletprocesspsbt", 4, "finalize" },
};
// clang-format on

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(std::string_view raw)
{
    UniValue parsed;
    if (!parsed.read(raw)) throw std::runtime_error(tfm::format("Error parsing JSON: %s", raw));
    return parsed;
}

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    /** Return arg_value as UniValue, and first parse it if it is a non-string parameter */
    UniValue ArgToUniValue(std::string_view arg_value, const std::string& method, int param_idx)
    {
        return members.count({method, param_idx}) > 0 ? ParseNonRFCJSONValue(arg_value) : arg_value;
    }

    /** Return arg_value as UniValue, and first parse it if it is a non-string parameter */
    UniValue ArgToUniValue(std::string_view arg_value, const std::string& method, const std::string& param_name)
    {
        return membersByName.count({method, param_name}) > 0 ? ParseNonRFCJSONValue(arg_value) : arg_value;
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    for (const auto& cp : vRPCConvertParams) {
        members.emplace(cp.methodName, cp.paramIdx);
        membersByName.emplace(cp.methodName, cp.paramName);
    }
}

static CRPCConvertTable rpcCvtTable;


UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        std::string_view value{strParams[idx]};
        params.push_back(rpcCvtTable.ArgToUniValue(value, strMethod, idx));
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);
    UniValue positional_args{UniValue::VARR};

    for (std::string_view s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            positional_args.push_back(rpcCvtTable.ArgToUniValue(s, strMethod, positional_args.size()));
            continue;
        }

        std::string name{s.substr(0, pos)};
        std::string_view value{s.substr(pos+1)};

        // Intentionally overwrite earlier named values with later ones as a
        // convenience for scripts and command line users that want to merge
        // options.
        params.pushKV(name, rpcCvtTable.ArgToUniValue(value, strMethod, name));
    }

    if (!positional_args.empty()) {
        // Use __pushKV instead of pushKV to avoid overwriting an explicit
        // "args" value with an implicit one. Let the RPC server handle the
        // request as given.
        params.pushKVEnd("args", positional_args); // peercoin bridge: __pushKV
    }

    return params;
}
