// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <tinyformat.h>
#include <util/system.h>

#include <algorithm>
#include <set>
#include <stdint.h>
#include <string>
#include <string_view>

//! Specify whether parameter should be parsed by bitcoin-cli as a JSON value,
//! or passed unchanged as a string, or a combination of both.
enum ParamFormat { JSON, STRING, JSON_OR_STRING };

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
    ParamFormat format{ParamFormat::JSON}; //!< parameter format
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
    { "analyzepsbt", 0, "psbt", ParamFormat::STRING },
    { "backupwallet", 0, "destination", ParamFormat::STRING },
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
    { "createwallet", 0, "wallet_name", ParamFormat::STRING },
    { "createwallet", 1, "disable_private_keys" },
    { "createwallet", 2, "blank" },
    { "createwallet", 3, "passphrase", ParamFormat::STRING },
    { "createwallet", 4, "avoid_reuse" },
    { "createwallet", 5, "descriptors" },
    { "createwallet", 6, "load_on_startup" },
    { "createwallet", 7, "external_signer" },
    { "createwalletdescriptor", 1, "internal" },
    { "createwalletdescriptor", 1, "options" },
    { "decodepsbt", 0, "psbt", ParamFormat::STRING },
    { "decoderawtransaction", 1, "iswitness" },
    { "deriveaddresses", 1, "range" },
    { "descriptorprocesspsbt", 0, "psbt", ParamFormat::STRING },
    { "descriptorprocesspsbt", 1, "descriptors" },
    { "descriptorprocesspsbt", 2, "sighashtype", ParamFormat::STRING },
    { "descriptorprocesspsbt", 3, "bip32derivs" },
    { "descriptorprocesspsbt", 4, "finalize" },
    { "disconnectnode", 1, "nodeid" },
    { "echoipc", 0, "arg", ParamFormat::STRING },
    { "encryptwallet", 0, "passphrase", ParamFormat::STRING },
    { "estimatesmartfee", 0, "conf_target" },
    { "finalizepsbt", 0, "psbt", ParamFormat::STRING },
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
    { "getaddressesbylabel", 0, "label", ParamFormat::STRING },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getbalance", 3, "avoid_reuse" },
    { "getblock", 1, "verbose" },
    { "getblock", 1, "verbosity" },
    { "getblockfrompeer", 1, "peer_id" },
    { "getblockhash", 0, "height" },
    { "getblockheader", 1, "verbose" },
    { "getblockstats", 0, "hash_or_height", ParamFormat::JSON_OR_STRING },
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
    { "getnewaddress", 0, "label", ParamFormat::STRING },
    { "getnewaddress", 1, "address_type", ParamFormat::STRING },
    { "getnodeaddresses", 0, "count" },
    { "getorphantxs", 0, "verbosity" },
    { "getrawmempool", 0, "verbose" },
    { "getrawmempool", 1, "mempool_sequence" },
    { "getrawtransaction", 1, "verbose" },
    { "getrawtransaction", 1, "verbosity" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaddress", 2, "include_immature_coinbase" },
    { "getreceivedbylabel", 0, "label", ParamFormat::STRING },
    { "getreceivedbylabel", 1, "minconf" },
    { "getreceivedbylabel", 2, "include_immature_coinbase" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettransaction", 2, "verbose" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "gettxoutsetinfo", 1, "hash_or_height", ParamFormat::JSON_OR_STRING },
    { "gettxoutsetinfo", 2, "use_index" },
    { "gettxspendingprevout", 0, "outputs" },
    { "gettxspendingprevout", 1, "mempool_only" },
    { "gettxspendingprevout", 1, "options" },
    { "gettxspendingprevout", 1, "return_spending_tx" },
    { "importcoinstake", 1, "timestamp" },
    { "importdescriptors", 0, "requests" },
    { "importmempool", 0, "filepath", ParamFormat::STRING },
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
    { "listsinceblock", 0, "blockhash", ParamFormat::STRING },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "listsinceblock", 4, "include_change" },
    { "listsinceblock", 5, "label", ParamFormat::STRING },
    { "listtransactions", 0, "label", ParamFormat::STRING },
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
    { "loadwallet", 0, "filename", ParamFormat::STRING },
    { "loadwallet", 1, "load_on_startup" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "lockunspent", 2, "persistent" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "migratewallet", 0, "wallet_name", ParamFormat::STRING },
    { "migratewallet", 1, "passphrase", ParamFormat::STRING },
    { "mockscheduler", 0, "delta_time" },
    { "optimizeutxoset", 1, "amount" },
    { "optimizeutxoset", 2, "transmit" },
    { "optimizeutxoset", 4, "force" },
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
    { "restorewallet", 0, "wallet_name", ParamFormat::STRING },
    { "restorewallet", 1, "backup_file", ParamFormat::STRING },
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
    { "sendmany", 0, "dummy", ParamFormat::STRING },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 3, "comment", ParamFormat::STRING },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5, "replaceable" },
    { "sendmany", 6, "conf_target" },
    { "sendmany", 7, "estimate_mode", ParamFormat::STRING },
    { "sendmany", 8, "fee_rate" },
    { "sendmany", 9, "verbose" },
    { "sendmsgtopeer", 0, "peer_id" },
    { "sendrawtransaction", 1, "maxfeerate" },
    { "sendrawtransaction", 2, "maxburnamount" },
    { "sendtoaddress", 0, "address", ParamFormat::STRING },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 2, "comment", ParamFormat::STRING },
    { "sendtoaddress", 3, "comment_to", ParamFormat::STRING },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 5, "replaceable" },
    { "sendtoaddress", 6, "conf_target" },
    { "sendtoaddress", 7, "estimate_mode", ParamFormat::STRING },
    { "sendtoaddress", 8, "avoid_reuse" },
    { "sendtoaddress", 9, "fee_rate" },
    { "sendtoaddress", 10, "verbose" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setlabel", 1, "label", ParamFormat::STRING },
    { "setmocktime", 0, "timestamp" },
    { "setnetworkactive", 0, "state" },
    { "setwalletflag", 1, "value" },
    { "signmessage", 1, "message", ParamFormat::STRING },
    { "signmessagewithprivkey", 1, "message", ParamFormat::STRING },
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
    { "unloadwallet", 0, "wallet_name", ParamFormat::STRING },
    { "unloadwallet", 1, "load_on_startup" },
    { "utxoupdatepsbt", 0, "psbt", ParamFormat::STRING },
    { "utxoupdatepsbt", 1, "descriptors" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "verifymessage", 1, "signature", ParamFormat::STRING },
    { "verifymessage", 2, "message", ParamFormat::STRING },
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
    { "walletpassphrase", 0, "passphrase", ParamFormat::STRING },
    { "walletpassphrase", 1, "timeout" },
    { "walletpassphrasechange", 0, "oldpassphrase", ParamFormat::STRING },
    { "walletpassphrasechange", 1, "newpassphrase", ParamFormat::STRING },
    { "walletprocesspsbt", 0, "psbt", ParamFormat::STRING },
    { "walletprocesspsbt", 1, "sign" },
    { "walletprocesspsbt", 2, "sighashtype", ParamFormat::STRING },
    { "walletprocesspsbt", 3, "bip32derivs" },
    { "walletprocesspsbt", 4, "finalize" },
};
// clang-format on

/** Parse string to UniValue or throw runtime_error if string contains invalid JSON */
static UniValue Parse(std::string_view raw, ParamFormat format = ParamFormat::JSON)
{
    UniValue parsed;
    if (!parsed.read(raw)) {
        if (format != ParamFormat::JSON_OR_STRING) throw std::runtime_error(tfm::format("Error parsing JSON: %s", raw));
        return UniValue(std::string(raw));
    }
    return parsed;
}

namespace rpc_convert
{
const CRPCConvertParam* FromPosition(std::string_view method, size_t pos)
{
    auto it = std::ranges::find_if(vRPCConvertParams, [&](const auto& p) {
        return p.methodName == method && p.paramIdx == static_cast<int>(pos);
    });

    return it == std::end(vRPCConvertParams) ? nullptr : &*it;
}

const CRPCConvertParam* FromName(std::string_view method, std::string_view name)
{
    auto it = std::ranges::find_if(vRPCConvertParams, [&](const auto& p) {
        return p.methodName == method && p.paramName == name;
    });

    return it == std::end(vRPCConvertParams) ? nullptr : &*it;
}
} // namespace rpc_convert

static UniValue ParseParam(const CRPCConvertParam* param, std::string_view raw)
{
    // Only parse parameters which have the JSON or JSON_OR_STRING format; otherwise, treat them as strings.
    return (param && (param->format == ParamFormat::JSON || param->format == ParamFormat::JSON_OR_STRING)) ? Parse(raw, param->format) : UniValue(std::string(raw));
}

/**
 * Convert command lines arguments to params object when -named is disabled.
 */
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (std::string_view s : strParams) {
        params.push_back(ParseParam(rpc_convert::FromPosition(strMethod, params.size()), s));
    }

    return params;
}

/**
 * Convert command line arguments to params object when -named is enabled.
 *
 * The -named syntax accepts named arguments in NAME=VALUE format, as well as
 * positional arguments without names. The syntax is inherently ambiguous if
 * names are omitted and values contain '=', so a heuristic is used to
 * disambiguate:
 *
 * - Arguments that do not contain '=' are treated as positional parameters.
 *
 * - Arguments that do contain '=' are assumed to be named parameters in
 *   NAME=VALUE format except for two special cases:
 *
 *   1. The case where NAME is not a known parameter name, and the next
 *      positional parameter requires a JSON value, and the argument parses as
 *      JSON. E.g. ["list", "with", "="].
 *
 *   2. The case where NAME is not a known parameter name and the next
 *      positional parameter requires a string value. E.g. "my=wallet".
 */
UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);
    UniValue positional_args{UniValue::VARR};

    for (std::string_view s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string_view::npos) {
            positional_args.push_back(ParseParam(rpc_convert::FromPosition(strMethod, positional_args.size()), s));
            continue;
        }

        std::string name{s.substr(0, pos)};
        std::string_view value{s.substr(pos+1)};

        const CRPCConvertParam* named_param{rpc_convert::FromName(strMethod, name)};
        if (!named_param) {
            const CRPCConvertParam* positional_param = rpc_convert::FromPosition(strMethod, positional_args.size());
            UniValue parsed_value;
            if (positional_param && positional_param->format == ParamFormat::JSON && parsed_value.read(s)) {
                positional_args.push_back(std::move(parsed_value));
                continue;
            } else if (positional_param && positional_param->format == ParamFormat::STRING) {
                positional_args.push_back(UniValue(std::string(s)));
                continue;
            }
        }

        // Intentionally overwrite earlier named values with later ones as a
        // convenience for scripts and command line users that want to merge
        // options.
        params.pushKV(name, ParseParam(named_param, value));
    }

    if (!positional_args.empty()) {
        // Use __pushKV instead of pushKV to avoid overwriting an explicit
        // "args" value with an implicit one. Let the RPC server handle the
        // request as given.
        params.pushKVEnd("args", positional_args); // peercoin bridge: __pushKV
    }

    return params;
}
