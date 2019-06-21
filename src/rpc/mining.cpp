// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <miner.h>
#include <net.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/script.h>
#include <shutdown.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fees.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/validation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbitsinfo.h>
#include <warnings.h>

#include <wallet/wallet.h>
#include <kernel.h>

#include <memory>
#include <stdint.h>

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = ::ChainActive().Tip();

    if (height >= 0 && height < ::ChainActive().Height())
        pb = ::ChainActive()[height];

    if (pb == nullptr || !pb->nHeight)
        return 0;

    //ppcTODO - redo this to fit peercoin
    // If lookup is -1, then use blocks since last difficulty change.
//    if (lookup <= 0)
//        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainTrust - pb0->nChainTrust;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static UniValue getnetworkhashps(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, /* default */ "120", "The number of blocks, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, /* default */ "-1", "To estimate at the time of the given height."},
                },
                RPCResult{
            "x             (numeric) Hashes per second estimated\n"
                },
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
            }.ToString());

    LOCK(cs_main);
    return GetNetworkHashPS(!request.params[0].isNull() ? request.params[0].get_int() : 120, !request.params[1].isNull() ? request.params[1].get_int() : -1);
}

// peercoin: get network Gh/s estimate
UniValue getnetworkghps(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getnetworkghps\n"
            "Returns a recent Ghash/second network mining estimate.");

    int64_t nTargetSpacingWorkMin = 30;
    int64_t nTargetSpacingWork = nTargetSpacingWorkMin;
    int64_t nInterval = 72;
    CBlockIndex* pindex = chainActive.Genesis();
    CBlockIndex* pindexPrevWork = chainActive.Genesis();
    while (pindex)
    {
        // Exponential moving average of recent proof-of-work block spacing
        if (pindex->IsProofOfWork())
        {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            nTargetSpacingWork = ((nInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nInterval + 1);
            nTargetSpacingWork = std::max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }
        pindex = chainActive.Next(pindex);
    }
    double dNetworkGhps = GetDifficulty() * 4.294967296 / nTargetSpacingWork;
    return dNetworkGhps;
}

static UniValue generateBlocks(const CScript& coinbase_script, int nGenerate, uint64_t nMaxTries, CWallet * const pwallet)
{
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = ::ChainActive().Height();
        nHeightEnd = nHeight+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (nHeight < nHeightEnd && !ShutdownRequested())
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbase_script));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, ::ChainActive().Tip(), nExtraNonce);
        }
        while (nMaxTries > 0 && pblock->nNonce < std::numeric_limits<uint32_t>::max() && !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus()) && !ShutdownRequested()) {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0 || ShutdownRequested()) {
            break;
        }
        if (pblock->nNonce == std::numeric_limits<uint32_t>::max()) {
            continue;
        }

        // peercoin: sign block
        // rfc6: we sign proof of work blocks only before 0.8 fork
        if (!IsBTC16BIPsEnabled(pblock->GetBlockTime()) && !SignBlock(*pblock, *pwallet))
            throw JSONRPCError(-100, "Unable to sign block, wallet locked?");

        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());
    }
    return blockHashes;
}

static UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            RPCHelpMan{"generatetoaddress",
                "\nMine blocks immediately to a specified address (before the RPC call returns)\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated immediately."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated peercoin to."},
                    {"maxtries", RPCArg::Type::NUM, /* default */ "1000000", "How many iterations to try."},
                },
                RPCResult{
            "[ blockhashes ]     (array) hashes of blocks generated\n"
                },
                RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are running the Peercoin wallet, you can get a new address to send the newly generated peercoin to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
            }.ToString());

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    CScript coinbase_script = GetScriptForDestination(destination);

    return generateBlocks(coinbase_script, nGenerate, nMaxTries, pwallet);
}

static UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    "{\n"
                    "  \"blocks\": nnn,             (numeric) The current block\n"
                    "  \"currentblockweight\": nnn, (numeric, optional) The block weight of the last assembled block (only present if a block was ever assembled)\n"
                    "  \"currentblocktx\": nnn,     (numeric, optional) The number of block transactions of the last assembled block (only present if a block was ever assembled)\n"
                    "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
                    "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
                    "  \"pooledtx\": n              (numeric) The size of the mempool\n"
                    "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
                    "  \"warnings\": \"...\"          (string) any network and blockchain warnings\n"
            "  \"errors\": \"...\"            (string) DEPRECATED. Same as warnings. Only shown when peercoind is started with -deprecatedrpc=getmininginfo\n"
                    "}\n"
                },
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
            }.ToString());
    }

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           (int)::ChainActive().Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("difficulty",       (double)GetDifficulty(::ChainActive().Tip()));
    obj.pushKV("networkhashps",    getnetworkhashps(request));
    obj.pushKV("networkghps",      getnetworkghps(request));
    obj.pushKV("chain",            Params().NetworkIDString());
    obj.pushKV("warnings",         GetWarnings("statusbar"));
    return obj;
}



// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, FormatStateMessage(state));
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"getblocktemplate",
                "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
                "It returns data needed to construct a block to work on.\n"
                "For full specification, see BIPs 22, 23, 9, and 145:\n"
                "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
                "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
                "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
                "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n",
                {
                    {"template_request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A json object in the following spec",
                        {
                            {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                            {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "A list of strings",
                                {
                                    {"support", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'"},
                                },
                                },
                            {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                                {
                                    {"support", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported softfork deployment"},
                                },
                                },
                        },
                        "\"template_request\""},
                },
                RPCResult{
            "{\n"
            "  \"version\" : n,                    (numeric) The preferred block version\n"
            "  \"rules\" : [ \"rulename\", ... ],    (array of strings) specific block rules that are to be enforced\n"
            "  \"vbavailable\" : {                 (json object) set of pending, supported versionbit (BIP 9) softfork deployments\n"
            "      \"rulename\" : bitnumber          (numeric) identifies the bit number as indicating acceptance and readiness for the named softfork rule\n"
            "      ,...\n"
            "  },\n"
            "  \"vbrequired\" : n,                 (numeric) bit mask of versionbits the server requires set in submissions\n"
            "  \"previousblockhash\" : \"xxxx\",     (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",             (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",             (string) transaction id encoded in little-endian hexadecimal\n"
            "         \"hash\" : \"xxxx\",             (string) hash encoded in little-endian hexadecimal (including witness data)\n"
            "         \"depends\" : [                (array) array of numbers \n"
            "             n                          (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                    (numeric) difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,                (numeric) total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero\n"
            "         \"weight\" : n,                (numeric) total transaction weight, as counted for purposes of block limits\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                 (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"xx\"                  (string) key name is to be ignored, and value included in scriptSig\n"
            "  },\n"
            "  \"coinbasevalue\" : n,              (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)\n"
            "  \"coinbasetxn\" : { ... },          (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",                (string) The hash target\n"
            "  \"mintime\" : xxx,                  (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                     (array of string) list of ways the block template may be changed \n"
            "     \"value\"                          (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",(string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"weightlimit\" : n,                (numeric) limit of block weight\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"
                },
                RPCExamples{
                    HelpExampleCli("getblocktemplate", "{\"rules\": [\"segwit\"]}")
            + HelpExampleRpc("getblocktemplate", "{\"rules\": [\"segwit\"]}")
                },
            }.ToString());

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    int64_t nMaxVersionPreVB = -1;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = ::ChainActive().Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } else {
            // NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) {
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");

    if (::ChainstateActive().IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is in initial sync and waiting for blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = ::ChainActive().Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WAIT_LOCK(g_best_block_mutex, lock);
            while (g_best_block == hashWatchedChain && IsRPCRunning())
            {
                if (g_best_block_cv.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    // without holding ::mempool.cs to avoid deadlocks
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    bool fSupportsSegwit = setClientRules.find("segwit") != setClientRules.end();
    // GBT must be called with 'segwit' set in the rules
    if (!fSupportsSegwit) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    if (pindexPrev != ::ChainActive().Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = ::ChainActive().Tip();
        nStart = GetTime();

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    assert(pindexPrev);
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock);
    pblock->nNonce = 0;

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = !IsBTC16BIPsEnabled(chainActive.Tip()->nTime);

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblocktemplate->vTxFees[index_in_template]);
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            assert(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.pushKV("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end()));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);

    UniValue aRules(UniValue::VARR);
    result.pushKV("version", pblock->nVersion);
    result.pushKV("rules", aRules);

    if (nMaxVersionPreVB >= 2) {
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        aMutable.push_back("version/force");
    }

    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    result.pushKV("coinbaseaux", aux);
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", ::ChainActive().Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    result.pushKV("noncerange", "00000000ffffffff");
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
    if (fPreSegWit) {
        assert(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        assert(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        result.pushKV("weightlimit", (int64_t)MAX_BLOCK_WEIGHT);
    }
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    if (!pblocktemplate->vchCoinbaseCommitment.empty()) {
        result.pushKV("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end()));
    }

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const CValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static UniValue submitblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"submitblock",
                "\nAttempts to submit new block to network.\n"
                "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
                    {"dummy", RPCArg::Type::STR, /* default */ "ignored", "dummy value, for compatibility with BIP22. This value is ignored."},
                },
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
            }.ToString());
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
        }
    }

    // peercoin: check block before attempting to sign it
    CValidationState state;
    if (!CheckBlock(block, state, Params().GetConsensus(), true,  true, false)) {
        LogPrintf("SubmitBlock: %s\n", FormatStateMessage(state));
        throw JSONRPCError(-100, "Block failed CheckBlock() function.");
        }

    // peercoin: sign block
    // rfc6: sign proof of stake blocks only after 0.8 fork
    if ((block.IsProofOfStake() || !IsBTC16BIPsEnabled(block.GetBlockTime())) && !SignBlock(block, *pwallet))
        throw JSONRPCError(-100, "Unable to sign block, wallet locked?");

    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            UpdateUncommittedBlockStructures(block, pindex, Params().GetConsensus());
        }
    }

    bool new_block;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool accepted = ProcessNewBlock(Params(), blockptr, /* fForceProcessing */ true, /* fNewBlock */ &new_block);
    UnregisterValidationInterface(&sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc.found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc.state);
}

static UniValue submitheader(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
            "None"
                },
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
            }.ToString());
    }

    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    {
        LOCK(cs_main);
        if (!LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    CValidationState state;
    ProcessNewBlockHeaders({h}, state, Params(), /* ppindex */ nullptr, /* first_invalid */ nullptr);
    if (state.IsValid()) return NullUniValue;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, FormatStateMessage(state));
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
}

static UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"estimatesmartfee",
                "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
                "confirmation within conf_target blocks if possible and return the number of blocks\n"
                "for which the estimate is valid. Uses virtual transaction size as defined\n"
                "in BIP 141 (witness data is discounted).\n",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "CONSERVATIVE", "The fee estimate mode.\n"
            "                   Whether to return a more conservative estimate which also satisfies\n"
            "                   a longer history. A conservative estimate potentially returns a\n"
            "                   higher feerate and is more likely to be sufficient for the desired\n"
            "                   target, but is not as responsive to short term drops in the\n"
            "                   prevailing fee market.  Must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\""},
                },
                RPCResult{
            "{\n"
            "  \"feerate\" : x.x,     (numeric, optional) estimate fee rate in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": [ str... ] (json array of strings, optional) Errors encountered during processing\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "The request target will be clamped between 2 and the highest target\n"
            "fee estimation is able to return based on how long it has been running.\n"
            "An error is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
                },
                RPCExamples{
                    HelpExampleCli("estimatesmartfee", "6")
                },
            }.ToString());

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("feerate", 0.01));
    result.push_back(Pair("blocks", chainActive.Height()));
    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getnetworkhashps",       &getnetworkhashps,       {"nblocks","height"} },
    { "mining",             "getmininginfo",          &getmininginfo,          {} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       {"template_request"} },
    { "mining",             "submitblock",            &submitblock,            {"hexdata","dummy"} },
    { "mining",             "submitheader",           &submitheader,           {"hexdata"} },


    { "generating",         "generatetoaddress",      &generatetoaddress,      {"nblocks","address","maxtries"} },

    { "util",               "estimatesmartfee",       &estimatesmartfee,       {"conf_target", "estimate_mode"} },
};
// clang-format on

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
