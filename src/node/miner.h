// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINER_H
#define BITCOIN_NODE_MINER_H

#include <interfaces/types.h>
#include <node/types.h>
#include <primitives/block.h>
#include <txmempool.h>
#include <node/context.h>
#include <util/signalinterrupt.h>
#include <atomic>
#include <memory>
#include <optional>
#include <stdint.h>
#include <wallet/wallet.h>

#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

extern std::atomic<int64_t> nLastCoinStakeSearchInterval;
extern std::thread m_minter_thread;

// peercoin: legacy LP selection bridge tags/comparators
struct ancestor_score;
struct CompareTxMemPoolEntryByAncestorFee {
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        auto fa = (double)a.GetModFeesWithAncestors() / (double)a.GetSizeWithAncestors();
        auto fb = (double)b.GetModFeesWithAncestors() / (double)b.GetSizeWithAncestors();
        if (fa != fb) return fa > fb;
        return a.GetTime() < b.GetTime();
    }
};

class Chainstate;
class ChainstateManager;

class CBlockIndex;
class CChainParams;
class CScript;

namespace Consensus { struct Params; };

namespace node {

static const bool DEFAULT_PRINT_MODIFIED_FEE = false;
static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate
{
    // peercoin: v31 mining stats
    std::vector<FeePerVSize> m_package_feerates;
    CoinbaseTx m_coinbase_tx;
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOpsCost;
    std::vector<unsigned char> vchCoinbaseCommitment;
};

/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    CAmount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t m_lock_time_cutoff;

    const CChainParams& chainparams;
    const CTxMemPool* const m_mempool;
    Chainstate& m_chainstate;

public:
    struct Options : BlockCreateOptions {
        // Configuration parameters for the block size
        size_t nBlockMaxWeight{DEFAULT_BLOCK_MAX_WEIGHT};
        CFeeRate blockMinFeeRate{DEFAULT_BLOCK_MIN_TX_FEE};
        // Whether to call TestBlockValidity() at the end of CreateNewBlock().
        bool test_block_validity{true};
        bool print_modified_fee{DEFAULT_PRINT_MODIFIED_FEE};
    };

    explicit BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool);
    explicit BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn, wallet::CWallet* pwallet=nullptr, bool* pfPoSCancel=nullptr, NodeContext* m_node=nullptr, CTxDestination destination=CNoDestination());
    //std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn);

    inline static std::optional<int64_t> m_last_block_num_txs{};
    inline static std::optional<int64_t> m_last_block_weight{};

private:
    const Options m_options;

    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(const CTxMemPoolEntry& entry);

    // peercoin: v31-era chunk-based selection (TxGraph BlockBuilder)
    void addChunks() EXCLUSIVE_LOCKS_REQUIRED(m_mempool->cs);
    bool TestChunkBlockLimits(FeePerWeight chunk_feerate, int64_t chunk_sigops_cost) const;
    bool TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const;
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

namespace boost {
    class thread_group;
} // namespace boost

void MintStake(NodeContext& m_node);
void StopStakeMinter();
bool StakeMinterStopRequested(const util::SignalInterrupt* shutdown_signal);

/** Update an old GenerateCoinbaseCommitment from CreateNewBlock after the block txs have changed */
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman);

/** Apply -blockmintxfee and -blockmaxweight options from ArgsManager to BlockAssembler options. */
void ApplyArgsManOptions(const ArgsManager& gArgs, BlockAssembler::Options& options);

// peercoin: v31 mining helpers
using interfaces::BlockRef;
class KernelNotifications;
std::optional<BlockRef> GetTip(ChainstateManager& chainman);
std::optional<BlockRef> WaitTipChanged(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const uint256& current_tip, MillisecondsDouble& timeout, bool& interrupt);
std::unique_ptr<CBlockTemplate> WaitAndCreateNewBlock(ChainstateManager& chainman, KernelNotifications& kernel_notifications, CTxMemPool* mempool, const std::unique_ptr<CBlockTemplate>& block_template, const BlockWaitOptions& options, const BlockAssembler::Options& assemble_options, bool& interrupt_wait);
void InterruptWait(KernelNotifications& kernel_notifications, bool& interrupt_wait);
bool CooldownIfHeadersAhead(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const BlockRef& last_tip, bool& interrupt_mining);
void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce);


} // namespace node

#endif // BITCOIN_NODE_MINER_H
