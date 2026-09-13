// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>
#include <util/signalinterrupt.h>
#include <interfaces/types.h>
#include <node/kernel_notifications.h>
#include <interfaces/wallet.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <validation.h>
#include <kernel.h>
#include <net.h>
#include <interfaces/chain.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <util/exception.h>
#include <util/thread.h>
#include <wallet/coincontrol.h>
#include <node/warnings.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <utility>

using wallet::CWallet;
using wallet::COutput;
using wallet::CCoinControl;
using wallet::ReserveDestination;

int64_t nLastCoinStakeSearchInterval = 0;
std::thread m_minter_thread;
static std::atomic_bool g_stake_minter_stop{false};

namespace node {

void StopStakeMinter()
{
    g_stake_minter_stop = true;
}

bool StakeMinterStopRequested(const util::SignalInterrupt* shutdown_signal)
{
    return g_stake_minter_stop.load() || (shutdown_signal && bool{*shutdown_signal});
}

static bool error(const bilingual_str& msg)
{
    LogPrintf("ERROR: %s\n", msg.original);
    return false;
}

template <class Rep, class Period>
static bool StakeMinterSleep(const util::SignalInterrupt* shutdown_signal, std::chrono::duration<Rep, Period> duration)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    while (std::chrono::steady_clock::now() < deadline) {
        if (StakeMinterStopRequested(shutdown_signal)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return !StakeMinterStopRequested(shutdown_signal);
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextTargetRequired(pindexPrev, false, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    // Limit weight to between 4K and DEFAULT_BLOCK_MAX_WEIGHT for sanity:
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, 4000, DEFAULT_BLOCK_MAX_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{mempool},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    options.nBlockMaxWeight = gArgs.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
}
static BlockAssembler::Options ConfiguredOptions()
{
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool)
    : BlockAssembler(chainstate, mempool, ConfiguredOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

// peercoin: if pwallet != NULL it will attempt to create coinstake
// peercoin bridge: PoS minter status for RPC (getstakinginfo)
std::string g_strMintWarning;
std::atomic<bool> g_fStaking{false};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, CWallet* pwallet, bool* pfPoSCancel, NodeContext* m_node, CTxDestination destination)
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if (!pblocktemplate.get()) {
        return nullptr;
    }
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience
    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());

    LOCK(::cs_main);

    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;

    if (pwallet == nullptr) {
        pblock->nBits = GetNextTargetRequired(pindexPrev, false, chainparams.GetConsensus());
        coinbaseTx.vout[0].nValue = GetProofOfWorkReward(pblock->nBits, pblock->nTime);
    }

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    // peercoin: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = pblock->nTime;  // only initialized at startup

#ifdef ENABLE_WALLET
    if (pwallet)  // attemp to find a coinstake
    {
        *pfPoSCancel = true;
        pblock->nBits = GetNextTargetRequired(pindexPrev, true, chainparams.GetConsensus());
        CMutableTransaction txCoinStake;
        // peercoin bridge: modern CMutableTransaction leaves nTime zero-initialized;
        // v0.16 semantics require the coinstake search time to be the current time.
        txCoinStake.nTime = GetAdjustedTime();
        int64_t nSearchTime = txCoinStake.nTime; // search to current time
        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            if (pwallet->CreateCoinStake(*m_node->chainman, pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake, destination))
            {
                if (txCoinStake.nTime >= std::max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - (IsProtocolV09(pindexPrev->GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9)))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    coinbaseTx.vout[0].SetEmpty();
                    coinbaseTx.nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(MakeTransactionRef(CTransaction(txCoinStake)));
                    *pfPoSCancel = false;
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
        if (*pfPoSCancel)
            return nullptr; // peercoin: there is no point to continue if we failed to create coinstake
        pblock->nFlags = CBlockIndex::BLOCK_PROOF_OF_STAKE;
    }
#endif

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->StartBlockBuilding();
        addChunks();
        m_mempool->StopBlockBuilding();
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    {
        int widx = GetWitnessCommitmentIndex(*pblock);
        if (widx != NO_WITNESS_COMMITMENT) {
            const auto& spk = pblock->vtx[0]->vout[widx].scriptPubKey;
            pblocktemplate->vchCoinbaseCommitment = std::vector<unsigned char>(spk.begin() + 6, spk.end());
        }
    }
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    if (pblock->IsProofOfStake())
        pblock->nTime      = pblock->vtx[1]->nTime; //same as coinstake timestamp
    pblock->nTime          = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
    pblock->nTime          = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - (IsProtocolV09(pindexPrev->GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9));
    if (pblock->IsProofOfWork())
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    if (m_options.test_block_validity) {
        if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
        }
    }
    const auto time_2{SteadyClock::now()};


    return std::move(pblocktemplate);
}

void BlockAssembler::AddToBlock(const CTxMemPoolEntry& entry)
{
    pblocktemplate->block.vtx.emplace_back(entry.GetSharedTx());
    pblocktemplate->vTxFees.push_back(entry.GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost());
    nBlockWeight += entry.GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += entry.GetSigOpCost();
    nFees += entry.GetFee();

    if (m_options.print_modified_fee) {
        LogInfo("fee rate %s txid %s\n",
                  CFeeRate(entry.GetModifiedFee(), entry.GetTxSize()).ToString(),
                  entry.GetTx().GetHash().ToString());
    }
}

bool BlockAssembler::TestChunkBlockLimits(FeePerWeight chunk_feerate, int64_t chunk_sigops_cost) const
{
    if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

bool BlockAssembler::TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const
{
    for (const auto tx : txs) {
        if (!IsFinalTx(tx.get().GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::addChunks()
{
    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> selected_transactions;
    selected_transactions.reserve(MAX_CLUSTER_COUNT_LIMIT);
    FeePerWeight chunk_feerate;

    // This fills selected_transactions
    chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
    FeePerVSize chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);

    while (selected_transactions.size() > 0) {
        // Check to see if min fee rate is still respected.
        if (chunk_feerate_vsize << m_options.blockMinFeeRate.GetFeePerVSize()) {
            // Everything else we might consider has a lower feerate
            return;
        }

        int64_t chunk_sig_ops = 0;
        for (const auto& tx : selected_transactions) {
            chunk_sig_ops += tx.get().GetSigOpCost();
        }

        // Check to see if this chunk will fit.
        if (!TestChunkBlockLimits(chunk_feerate, chunk_sig_ops) || !TestChunkTransactions(selected_transactions)) {
            // This chunk won't fit, so we skip it and will try the next best one.
            m_mempool->SkipBuilderChunk();
            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
                    BLOCK_FULL_ENOUGH_WEIGHT_DELTA > m_options.nBlockMaxWeight) {
                // Give up if we're close to full and haven't succeeded in a while
                return;
            }
        } else {
            m_mempool->IncludeBuilderChunk();

            // This chunk will fit, so add it to the block.
            nConsecutiveFailed = 0;
            for (const auto& tx : selected_transactions) {
                AddToBlock(tx);
            }
            pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize);
        }

        selected_transactions.clear();
        chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
        chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);
    }
}









void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock) {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce));
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}


static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams, NodeContext& m_node)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != m_node.chainman->ActiveChain().Tip()->GetBlockHash())
            return error(Untranslated("PeercoinMiner: generated block is stale"));
    }

    // Process this block the same as if we had received it from another node
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!m_node.chainman->ProcessNewBlock(shared_pblock, true, true, NULL))
        return error(Untranslated("ProcessNewBlock, block not accepted"));

    return true;
}

void PoSMiner(NodeContext& m_node)
{
    std::string strMintMessage = _("Info: Minting suspended due to locked wallet.");
    std::string strMintSyncMessage = _("Info: Minting suspended while synchronizing wallet.");
    std::string strMintDisabledMessage = _("Info: Minting disabled by 'nominting' option.");
    std::string strMintBlockMessage = _("Info: Minting suspended due to block creation failure.");
    std::string strMintEmpty = "";
#ifdef ENABLE_WALLET
    if (!gArgs.GetBoolArg("-minting", true) || !gArgs.GetBoolArg("-staking", true))
    {
#endif
        g_strMintWarning = strMintDisabledMessage;
        LogPrintf("proof-of-stake minter disabled\n");
        return;
#ifdef ENABLE_WALLET
    }

    CConnman* connman = m_node.connman.get();
    std::string strMintNoWalletMessage = _("Info: Minting suspended due to no loaded wallet.");
    // ppctodo: deal with multiple wallets better
    auto get_wallet = [&]() -> std::shared_ptr<CWallet> {
        if (!m_node.wallet_loader || !m_node.wallet_loader->context()) return nullptr;
        auto wallets = wallet::GetWallets(*m_node.wallet_loader->context());
        return wallets.empty() ? nullptr : wallets.front();
    };
    auto sleep_or_stop = [&](auto duration) {
        return StakeMinterSleep(m_node.shutdown_signal, duration);
    };

    bool renamed = false;
    bool have_destination = false;
    std::weak_ptr<CWallet> destination_wallet;
    CTxDestination dest;
    unsigned int pos_timio = 500;
    unsigned int nExtraNonce = 0;

    try {
        bool fNeedToClear = false;
        while (true) {
            if (StakeMinterStopRequested(m_node.shutdown_signal)) return;

            std::shared_ptr<CWallet> wallet = get_wallet();
            if (!wallet) {
                g_fStaking = false;
                have_destination = false;
                destination_wallet.reset();
                if (g_strMintWarning != strMintNoWalletMessage) {
                    g_strMintWarning = strMintNoWalletMessage;
                    uiInterface.NotifyAlertChanged();
                }
                if (!sleep_or_stop(std::chrono::milliseconds(500))) return;
                continue;
            }

            if (!renamed) {
                g_fStaking = true; // peercoin bridge
                LogPrintf("CPUMiner started for proof-of-stake\n");
                util::ThreadRename("peercoin-stake-minter");
                renamed = true;
            }

            if (!have_destination || destination_wallet.lock() != wallet) {
                LOCK2(cs_main, wallet->cs_wallet);
                const std::string label = "mintkey";
                CTxDestination mint_dest;
                wallet->ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label, bool _is_change, const std::optional<wallet::AddressPurpose>& _purpose) {
                    if (_is_change) return;
                    if (_label == label)
                        mint_dest = _dest;
                });

                if (std::get_if<CNoDestination>(&mint_dest)) {
                    auto op_dest = wallet->GetNewDestination(OutputType::LEGACY, label);
                    if (!op_dest)
                        throw std::runtime_error("Error: Keypool ran out, please call keypoolrefill first.");
                    mint_dest = *op_dest;
                }

                wallet::CoinsResult availableCoins;
                CCoinControl coincontrol;
                availableCoins = AvailableCoins(*wallet, &coincontrol);
                pos_timio = 500 + 30 * sqrt(availableCoins.Size());
                LogPrintf("Set proof-of-stake timeout: %ums for %u UTXOs\n", pos_timio, availableCoins.Size());

                dest = mint_dest;
                destination_wallet = wallet;
                have_destination = true;
            }

            while (wallet->IsLocked()) {
                if (g_strMintWarning != strMintMessage) {
                    g_strMintWarning = strMintMessage;
                    uiInterface.NotifyAlertChanged();
                }
                fNeedToClear = true;
                if (!sleep_or_stop(std::chrono::seconds(3))) return;
                wallet = get_wallet();
                if (!wallet) {
                    if (!sleep_or_stop(std::chrono::milliseconds(500))) return;
                    continue;
                }
                if (destination_wallet.lock() != wallet) have_destination = false;
            }

            if (false /* ppport: v31 dropped MiningRequiresPeers; solo staking allowed */) {
                while (connman == nullptr || connman->GetNodeCount(ConnectionDirection::Both) == 0 || m_node.chainman->IsInitialBlockDownload()) {
                    while (connman == nullptr) {
                        if (!sleep_or_stop(std::chrono::seconds(1))) return;
                    }
                    if (!sleep_or_stop(std::chrono::seconds(10))) return;
                    wallet = get_wallet();
                    if (!wallet) {
                        if (!sleep_or_stop(std::chrono::milliseconds(500))) return;
                        continue;
                    }
                    if (destination_wallet.lock() != wallet) have_destination = false;
                }
            }

            CBlockIndex* pindexPrev{nullptr};
            // peercoin: never sleep while holding cs_main (starves msghand/opencon during IBD)
            while (true)
            {
                double progress{0.0};
                {
                    LOCK(cs_main);
                    pindexPrev = m_node.chainman->ActiveChain().Tip();
                    progress = m_node.chainman->GuessVerificationProgress(pindexPrev);
                }
                if (progress >= 0.996) break;
                LogPrintf("Minter thread sleeps while sync at %f\n", progress);
                if (g_strMintWarning != strMintSyncMessage) {
                    g_strMintWarning = strMintSyncMessage;
                    uiInterface.NotifyAlertChanged();
                }
                fNeedToClear = true;
                if (!sleep_or_stop(std::chrono::seconds(10))) return;
                wallet = get_wallet();
                if (!wallet) {
                    if (!sleep_or_stop(std::chrono::milliseconds(500))) return;
                    continue;
                }
                if (destination_wallet.lock() != wallet) have_destination = false;
            }
            if (fNeedToClear) {
                g_strMintWarning = strMintEmpty;
                uiInterface.NotifyAlertChanged();
                fNeedToClear = false;
            }

            //
            // Create new block
            //
            bool fPoSCancel = false;
            CBlock *pblock = nullptr;
            std::unique_ptr<CBlockTemplate> pblocktemplate;

            try {
                pblocktemplate = BlockAssembler(m_node.chainman->ActiveChainstate(), m_node.mempool.get()).CreateNewBlock(GetScriptForDestination(dest), wallet.get(), &fPoSCancel, &m_node, dest);
            }
            catch (const std::runtime_error &e)
            {
                LogPrintf("PeercoinMiner runtime error: %s\n", e.what());
                continue;
            }

            if (!pblocktemplate.get())
            {
                if (fPoSCancel == true)
                {
                    if (!sleep_or_stop(std::chrono::milliseconds(pos_timio))) return;
                    continue;
                }
                g_strMintWarning = strMintBlockMessage;
                uiInterface.NotifyAlertChanged();
                LogPrintf("Error in PeercoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                if (!sleep_or_stop(std::chrono::seconds(10))) return;
                continue;
            }
            pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            // peercoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                {
                    LOCK(wallet->cs_wallet);
                    if (!SignBlock(*pblock, *wallet))
                    {
                        LogPrintf("PoSMiner(): failed to sign PoS block\n");
                        continue;
                    }
                }
                LogPrintf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString());
                try {
                    ProcessBlockFound(pblock, Params(), m_node);
                }
                catch (const std::runtime_error &e)
                {
                    LogPrintf("PeercoinMiner runtime error: %s\n", e.what());
                    continue;
                }
                if (!sleep_or_stop(std::chrono::seconds(60 + GetRand(4)))) return;
            }
            if (!sleep_or_stop(std::chrono::milliseconds(pos_timio))) return;
        }
    }
    catch (const std::exception& e)
    {
        LogPrintf("PeercoinMiner runtime error: %s\n", e.what());
        return;
    }
#endif
}

// peercoin: stake minter thread
void static ThreadStakeMinter(NodeContext& m_node)
{
    LogPrintf("ThreadStakeMinter started\n");
    while (!StakeMinterStopRequested(m_node.shutdown_signal)) {
        try
        {
            PoSMiner(m_node);
            break;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ThreadStakeMinter()");
            StakeMinterSleep(m_node.shutdown_signal, std::chrono::seconds(1));
        } catch (...) {
            PrintExceptionContinue(NULL, "ThreadStakeMinter()");
            StakeMinterSleep(m_node.shutdown_signal, std::chrono::seconds(1));
        }
    }
    LogPrintf("ThreadStakeMinter exiting\n");
}

// peercoin: stake minter
void MintStake(NodeContext& m_node)
{
    if (m_minter_thread.joinable()) return;
    g_stake_minter_stop = false;
    m_minter_thread = std::thread([&] { util::TraceThread("minter", [&] { ThreadStakeMinter(m_node); }); });
}
std::unique_ptr<CBlockTemplate> WaitAndCreateNewBlock(ChainstateManager& chainman,
                                                      KernelNotifications& kernel_notifications,
                                                      CTxMemPool* mempool,
                                                      const std::unique_ptr<CBlockTemplate>& block_template,
                                                      const BlockWaitOptions& options,
                                                      const BlockAssembler::Options& assemble_options,
                                                      bool& interrupt_wait)
{
    // Delay calculating the current template fees, just in case a new block
    // comes in before the next tick.
    CAmount current_fees = -1;

    // Alternate waiting for a new tip and checking if fees have risen.
    // The latter check is expensive so we only run it once per second.
    auto now{NodeClock::now()};
    const auto deadline = now + options.timeout;
    const MillisecondsDouble tick{1000};
    const bool allow_min_difficulty{chainman.GetParams().GetConsensus().fPowAllowMinDifficultyBlocks};

    do {
        bool tip_changed{false};
        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            // Note that wait_until() checks the predicate before waiting
            kernel_notifications.m_tip_block_cv.wait_until(lock, std::min(now + tick, deadline), [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                AssertLockHeld(kernel_notifications.m_tip_block_mutex);
                const auto tip_block{kernel_notifications.TipBlock()};
                // We assume tip_block is set, because this is an instance
                // method on BlockTemplate and no template could have been
                // generated before a tip exists.
                tip_changed = Assume(tip_block) && tip_block != block_template->block.hashPrevBlock;
                return tip_changed || chainman.m_interrupt || interrupt_wait;
            });
            if (interrupt_wait) {
                interrupt_wait = false;
                return nullptr;
            }
        }

        if (chainman.m_interrupt) return nullptr;
        // At this point the tip changed, a full tick went by or we reached
        // the deadline.

        // Must release m_tip_block_mutex before locking cs_main, to avoid deadlocks.
        LOCK(::cs_main);

        // On test networks return a minimum difficulty block after 20 minutes
        if (!tip_changed && allow_min_difficulty) {
            const NodeClock::time_point tip_time{std::chrono::seconds{chainman.ActiveChain().Tip()->GetBlockTime()}};
            if (now > tip_time + 20min) {
                tip_changed = true;
            }
        }

        /**
         * We determine if fees increased compared to the previous template by generating
         * a fresh template. There may be more efficient ways to determine how much
         * (approximate) fees for the next block increased, perhaps more so after
         * Cluster Mempool.
         *
         * We'll also create a new template if the tip changed during this iteration.
         */
        if (options.fee_threshold < MAX_MONEY || tip_changed) {
            auto new_tmpl{BlockAssembler{
                chainman.ActiveChainstate(),
                mempool,
                assemble_options}
                              .CreateNewBlock(CScript(), nullptr, nullptr, nullptr)};

            // If the tip changed, return the new template regardless of its fees.
            if (tip_changed) return new_tmpl;

            // Calculate the original template total fees if we haven't already
            if (current_fees == -1) {
                current_fees = std::accumulate(block_template->vTxFees.begin(), block_template->vTxFees.end(), CAmount{0});
            }

            // Check if fees increased enough to return the new template
            const CAmount new_fees = std::accumulate(new_tmpl->vTxFees.begin(), new_tmpl->vTxFees.end(), CAmount{0});
            Assume(options.fee_threshold != MAX_MONEY);
            if (new_fees >= current_fees + options.fee_threshold) return new_tmpl;
        }

        now = NodeClock::now();
    } while (now < deadline);

    return nullptr;
}

void InterruptWait(KernelNotifications& kernel_notifications, bool& interrupt_wait)
{
    LOCK(kernel_notifications.m_tip_block_mutex);
    interrupt_wait = true;
    kernel_notifications.m_tip_block_cv.notify_all();
}

bool CooldownIfHeadersAhead(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const BlockRef& last_tip, bool& interrupt_mining)
{
    uint256 last_tip_hash{last_tip.hash};

    while (const std::optional<int> remaining = chainman.BlocksAheadOfTip()) {
        const int cooldown_seconds = std::clamp(*remaining, 3, 20);
        const auto cooldown_deadline{MockableSteadyClock::now() + std::chrono::seconds{cooldown_seconds}};

        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            kernel_notifications.m_tip_block_cv.wait_until(lock, cooldown_deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                const auto tip_block = kernel_notifications.TipBlock();
                return chainman.m_interrupt || interrupt_mining || (tip_block && *tip_block != last_tip_hash);
            });
            if (chainman.m_interrupt || interrupt_mining) {
                interrupt_mining = false;
                return false;
            }

            // If the tip changed during the wait, extend the deadline
            const auto tip_block = kernel_notifications.TipBlock();
            if (tip_block && *tip_block != last_tip_hash) {
                last_tip_hash = *tip_block;
                continue;
            }
        }

        // No tip change and the cooldown window has expired.
        if (MockableSteadyClock::now() >= cooldown_deadline) break;
    }

    return true;
}

void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Reset cached checks
    block.m_checked_witness_commitment = false;
    block.m_checked_merkle_root = false;
    block.fChecked = false;
}

std::optional<BlockRef> GetTip(ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!tip) return {};
    return BlockRef{tip->GetBlockHash(), tip->nHeight};
}

std::optional<BlockRef> WaitTipChanged(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const uint256& current_tip, MillisecondsDouble& timeout, bool& interrupt)
{
    Assume(timeout >= 0ms); // No internal callers should use a negative timeout
    if (timeout < 0ms) timeout = 0ms;
    if (timeout > std::chrono::years{100}) timeout = std::chrono::years{100}; // Upper bound to avoid UB in std::chrono
    auto deadline{std::chrono::steady_clock::now() + timeout};
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        // For callers convenience, wait longer than the provided timeout
        // during startup for the tip to be non-null. That way this function
        // always returns valid tip information when possible and only
        // returns null when shutting down, not when timing out.
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || chainman.m_interrupt || interrupt;
        });
        if (chainman.m_interrupt || interrupt) {
            interrupt = false;
            return {};
        }
        // At this point TipBlock is set, so continue to wait until it is
        // different then `current_tip` provided by caller.
        kernel_notifications.m_tip_block_cv.wait_until(lock, deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return Assume(kernel_notifications.TipBlock()) != current_tip || chainman.m_interrupt || interrupt;
        });
        if (chainman.m_interrupt || interrupt) {
            interrupt = false;
            return {};
        }
    }

    // Must release m_tip_block_mutex before getTip() locks cs_main, to
    // avoid deadlocks.
    return GetTip(chainman);
}

} // namespace node
