// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <flatfile.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <index/txindex.h>
#include <logging.h>
#include <logging/timer.h>
#include <net.h>
#include <node/blockstorage.h>
#include <node/coinstats.h>
#include <node/ui_interface.h>
#include <node/utxo_snapshot.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <signet.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h> // For NDEBUG compile time check
#include <util/hasher.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <algorithm>
#include <numeric>
#include <optional>
#include <kernel.h>
#include <bignum.h>
#include <wallet/wallet.h>

#include <string>

#include <boost/algorithm/string/replace.hpp>

using node::BLOCKFILE_CHUNK_SIZE;
using node::BlockManager;
using node::BlockMap;
using node::CBlockIndexWorkComparator;
using node::CCoinsStats;
using node::CoinStatsHashType;
using node::GetUTXOStats;
using node::OpenBlockFile;
using node::ReadBlockFromDisk;
using node::SnapshotMetadata;
using node::UNDOFILE_CHUNK_SIZE;
using node::UndoReadFromDisk;
using node::fImporting;
using node::fReindex;

#define MICRO 0.000001
#define MILLI 0.001

/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static const unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10000;
/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** Time to wait between writing blocks/block index to disk. */
static constexpr std::chrono::hours DATABASE_WRITE_INTERVAL{1};
/** Time to wait between flushing chainstate to disk. */
static constexpr std::chrono::hours DATABASE_FLUSH_INTERVAL{24};
/** Maximum age of our tip for us to be considered current for fee estimation */
static constexpr std::chrono::hours MAX_FEE_ESTIMATION_TIP_AGE{3};
const std::vector<std::string> CHECKLEVEL_DOC {
    "level 0 reads the blocks from disk",
    "level 1 verifies block validity",
    "level 2 verifies undo data",
    "level 3 checks disconnection of tip blocks",
    "level 4 tries to reconnect the blocks",
    "each level includes the checks of the previous levels",
};

bool CBlockIndexWorkComparator::operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
    // First sort by most total work, ...
    if (pa->nChainTrust > pb->nChainTrust) return false;
    if (pa->nChainTrust < pb->nChainTrust) return true;

    // ... then by earliest time received, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;

    // Use pointer address as tie breaker (should only happen with blocks
    // loaded from disk, as those all have id 0).
    if (pa < pb) return false;
    if (pa > pb) return true;

    // Identical blocks.
    return false;
}

uint256 vStakeSeen[1024];
/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

CBlockIndex *pindexBestHeader = nullptr;
Mutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
uint256 g_best_block;
bool g_parallel_script_checks{false};
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

CTxMemPool mempool;
CBlockIndex* CChainState::FindForkInGlobalIndex(const CBlockLocator& locator) const
{
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const uint256& hash : locator.vHave) {
        CBlockIndex* pindex{m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (m_chain.Contains(pindex)) {
                return pindex;
            }
            if (pindex->GetAncestor(m_chain.Height()) == m_chain.Tip()) {
                return m_chain.Tip();
            }
        }
    }
    return m_chain.Genesis();
}

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck>* pvChecks = nullptr)
                       EXCLUSIVE_LOCKS_REQUIRED(cs_main);

bool CheckFinalTx(const CBlockIndex* active_chain_tip, const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);
    assert(active_chain_tip); // TODO: Make active_chain_tip a reference

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses active_chain_tip.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than active_chain_tip.Height().
    const int nBlockHeight = active_chain_tip->nHeight + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? active_chain_tip->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool CheckSequenceLocks(CBlockIndex* tip,
                        const CCoinsView& coins_view,
                        const CTransaction& tx,
                        int flags,
                        LockPoints* lp,
                        bool useExistingLockPoints)
{
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses active_chainstate.m_chain.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than active_chainstate.m_chain.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!coins_view.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (const int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, CCoinsViewCache& coins_cache, size_t limit, std::chrono::seconds age)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs)
{
    AssertLockHeld(::cs_main);
    AssertLockHeld(pool.cs);
    int expired = pool.Expire(GetTime<std::chrono::seconds>() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        coins_cache.Uncache(removed);
}

void CChainState::MaybeUpdateMempoolForReorg(
    DisconnectedBlockTransactions& disconnectpool,
    bool fAddToMempool)
{
    if (!m_mempool) return;

    AssertLockHeld(cs_main);
    AssertLockHeld(m_mempool->cs);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        if (!fAddToMempool || (*it)->IsCoinBase() || (*it)->IsCoinStake() ||
            AcceptToMemoryPool(*this, *it, GetTime(),
                /*bypass_limits=*/true, /*test_accept=*/false).m_result_type !=
                    MempoolAcceptResult::ResultType::VALID) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            m_mempool->removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (m_mempool->exists(GenTxid::Txid((*it)->GetHash()))) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    const uint64_t ancestor_count_limit = gArgs.GetIntArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
    const uint64_t ancestor_size_limit = gArgs.GetIntArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
    m_mempool->UpdateTransactionsFromBlock(vHashUpdate, ancestor_size_limit, ancestor_count_limit);

    // Predicate to use for filtering transactions in removeForReorg.
    // Checks whether the transaction is still final and, if it spends a coinbase output, mature.
    // Also updates valid entries' cached LockPoints if needed.
    // If false, the tx is still valid and its lockpoints are updated.
    // If true, the tx would be invalid in the next block; remove this entry and all of its descendants.
    const auto filter_final_and_mature = [this, flags=STANDARD_LOCKTIME_VERIFY_FLAGS](CTxMemPool::txiter it)
        EXCLUSIVE_LOCKS_REQUIRED(m_mempool->cs, ::cs_main) {
        AssertLockHeld(m_mempool->cs);
        AssertLockHeld(::cs_main);
        const CTransaction& tx = it->GetTx();

        // The transaction must be final.
        if (!CheckFinalTx(m_chain.Tip(), tx, flags)) return true;
        LockPoints lp = it->GetLockPoints();
        const bool validLP{TestLockPointValidity(m_chain, lp)};
        CCoinsViewMemPool view_mempool(&CoinsTip(), *m_mempool);
        // CheckSequenceLocks checks if the transaction will be final in the next block to be
        // created on top of the new chain. We use useExistingLockPoints=false so that, instead of
        // using the information in lp (which might now refer to a block that no longer exists in
        // the chain), it will update lp to contain LockPoints relevant to the new chain.
        if (!CheckSequenceLocks(m_chain.Tip(), view_mempool, tx, flags, &lp, validLP)) {
            // If CheckSequenceLocks fails, remove the tx and don't depend on the LockPoints.
            return true;
        } else if (!validLP) {
            // If CheckSequenceLocks succeeded, it also updated the LockPoints.
            // Now update the mempool entry lockpoints as well.
            m_mempool->mapTx.modify(it, [&lp](CTxMemPoolEntry& e) { e.UpdateLockPoints(lp); });
        }

        // If the transaction spends any coinbase outputs, it must be mature.
        if (it->GetSpendsCoinbase()) {
            for (const CTxIn& txin : tx.vin) {
                auto it2 = m_mempool->mapTx.find(txin.prevout.hash);
                if (it2 != m_mempool->mapTx.end())
                    continue;
                const Coin& coin{CoinsTip().AccessCoin(txin.prevout)};
                assert(!coin.IsSpent());
                const auto mempool_spend_height{m_chain.Tip()->nHeight + 1};
                if (coin.IsCoinBase() && mempool_spend_height - coin.nHeight < COINBASE_MATURITY) {
                    return true;
                }
            }
        }
        // Transaction is still valid and cached LockPoints are updated.
        return false;
    };

    // We also need to remove any now-immature transactions
    m_mempool->removeForReorg(m_chain, filter_final_and_mature);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(
        *m_mempool,
        this->CoinsTip(),
        gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
        std::chrono::hours{gArgs.GetIntArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
}

/**
* Checks to avoid mempool polluting consensus critical paths since cached
* signature and script validity results will be reused if we validate this
* transaction again during block validation.
* */
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, TxValidationState& state,
                const CCoinsViewCache& view, const CTxMemPool& pool,
                unsigned int flags, PrecomputedTransactionData& txdata, CCoinsViewCache& coins_tip)
                EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    assert(!tx.IsCoinBase() && !tx.IsCoinStake());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // This coin was checked in PreChecks and MemPoolAccept
        // has been holding cs_main since then.
        Assume(!coin.IsSpent());
        if (coin.IsSpent()) return false;

        // If the Coin is available, there are 2 possibilities:
        // it is available in our current ChainstateActive UTXO set,
        // or it's a UTXO provided by a transaction in our mempool.
        // Ensure the scriptPubKeys in Coins from CoinsView are correct.
        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromUTXOSet = coins_tip.AccessCoin(txin.prevout);
            assert(!coinFromUTXOSet.IsSpent());
            assert(coinFromUTXOSet.out == coin.out);
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against current tip consensus rules.
    return CheckInputScripts(tx, state, view, flags, /* cacheSigStore= */ true, /* cacheFullScriptStore= */ true, txdata);
}

namespace {

class MemPoolAccept
{
public:
    explicit MemPoolAccept(CTxMemPool& mempool, CChainState& active_chainstate) : m_pool(mempool), m_view(&m_dummy), m_viewmempool(&active_chainstate.CoinsTip(), m_pool), m_active_chainstate(active_chainstate),
        m_limit_ancestors(gArgs.GetIntArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT)),
        m_limit_ancestor_size(gArgs.GetIntArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000),
        m_limit_descendants(gArgs.GetIntArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT)),
        m_limit_descendant_size(gArgs.GetIntArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000) {
    }

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const CChainParams& m_chainparams;
        const int64_t m_accept_time;
        const bool m_bypass_limits;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint>& m_coins_to_uncache;
        const bool m_test_accept;
        /** Whether we allow transactions to replace mempool transactions by BIP125 rules. If false,
         * any transaction spending the same inputs as a transaction in the mempool is considered
         * a conflict. */
        const bool m_allow_bip125_replacement;
        /** When true, the mempool will not be trimmed when individual transactions are submitted in
         * Finalize(). Instead, limits should be enforced at the end to ensure the package is not
         * partially submitted.
         */
        const bool m_package_submission;

        /** Parameters for single transaction mempool validation. */
        static ATMPArgs SingleAccept(const CChainParams& chainparams, int64_t accept_time,
                                     bool bypass_limits, std::vector<COutPoint>& coins_to_uncache,
                                     bool test_accept) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ bypass_limits,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ test_accept,
                            /* m_allow_bip125_replacement */ true,
                            /* m_package_submission */ false,
            };
        }

        /** Parameters for test package mempool validation through testmempoolaccept. */
        static ATMPArgs PackageTestAccept(const CChainParams& chainparams, int64_t accept_time,
                                          std::vector<COutPoint>& coins_to_uncache) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ true,
                            /* m_allow_bip125_replacement */ false,
                            /* m_package_submission */ false, // not submitting to mempool
            };
        }

        /** Parameters for child-with-unconfirmed-parents package validation. */
        static ATMPArgs PackageChildWithParents(const CChainParams& chainparams, int64_t accept_time,
                                                std::vector<COutPoint>& coins_to_uncache) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ false,
                            /* m_allow_bip125_replacement */ false,
                            /* m_package_submission */ true,
            };
        }
        // No default ctor to avoid exposing details to clients and allowing the possibility of
        // mixing up the order of the arguments. Use static functions above instead.
        ATMPArgs() = delete;
    };

    // Single transaction acceptance
    MempoolAcceptResult AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
    * Multiple transaction acceptance. Transactions may or may not be interdependent, but must not
    * conflict with each other, and the transactions cannot already be in the mempool. Parents must
    * come before children if any dependencies exist.
    */
    PackageMempoolAcceptResult AcceptMultipleTransactions(const std::vector<CTransactionRef>& txns, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Package (more specific than just multiple transactions) acceptance. Package must be a child
     * with all of its unconfirmed parents, and topologically sorted.
     */
    PackageMempoolAcceptResult AcceptPackage(const Package& package, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        explicit Workspace(const CTransactionRef& ptx) : m_ptx(ptx), m_hash(ptx->GetHash()) {}
        /** Txids of mempool transactions that this transaction directly conflicts with. */
        std::set<uint256> m_conflicts;
        /** Iterators to mempool entries that this transaction directly conflicts with. */
        CTxMemPool::setEntries m_iters_conflicting;
        /** Iterators to all mempool entries that would be replaced by this transaction, including
         * those it directly conflicts with and their descendants. */
        CTxMemPool::setEntries m_all_conflicting;
        /** All mempool ancestors of this transaction. */
        CTxMemPool::setEntries m_ancestors;
        /** Mempool entry constructed for this transaction. Constructed in PreChecks() but not
         * inserted into the mempool until Finalize(). */
        std::unique_ptr<CTxMemPoolEntry> m_entry;
        /** Pointers to the transactions that have been removed from the mempool and replaced by
         * this transaction, used to return to the MemPoolAccept caller. Only populated if
         * validation is successful and the original transactions are removed. */
        std::list<CTransactionRef> m_replaced_transactions;

        /** Virtual size of the transaction as used by the mempool, calculated using serialized size
         * of the transaction and sigops. */
        int64_t m_vsize;
        /** Fees paid by this transaction: total input amounts subtracted by total output amounts. */
        CAmount m_base_fees;
        /** Base fees + any fee delta set by the user with prioritisetransaction. */
        CAmount m_modified_fees;
        /** Total modified fees of all transactions being replaced. */
        CAmount m_conflicting_fees{0};
        /** Total virtual size of all transactions being replaced. */
        size_t m_conflicting_size{0};

        const CTransactionRef& m_ptx;
        /** Txid. */
        const uint256& m_hash;
        TxValidationState m_state;
        /** A temporary cache containing serialized transaction data for signature verification.
         * Reused across PolicyScriptChecks and ConsensusScriptChecks. */
        PrecomputedTransactionData m_precomputed_txdata;
    };

    // Run the policy checks on a given transaction, excluding any script checks.
    // Looks up inputs, calculates feerate, considers replacement, evaluates
    // package limits, etc. As this function can be invoked for "free" by a peer,
    // only tests that are fast should be done here (to avoid CPU DoS).
    bool PreChecks(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Enforce package mempool ancestor/descendant limits (distinct from individual
    // ancestor/descendant limits done in PreChecks).
    bool PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                              PackageValidationState& package_state) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run the script checks using our policy flags. As this can be slow, we should
    // only invoke this on transactions that have otherwise passed policy checks.
    bool PolicyScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Try to add the transaction to the mempool, removing any conflicts first.
    // Returns true if the transaction is in the mempool after any size
    // limiting is performed, false otherwise.
    bool Finalize(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Submit all transactions to the mempool and call ConsensusScriptChecks to add to the script
    // cache - should only be called after successful validation of all transactions in the package.
    // The package may end up partially-submitted after size limiting; returns true if all
    // transactions are successfully added to the mempool, false otherwise.
    bool SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces, PackageValidationState& package_state,
                       std::map<const uint256, const MempoolAcceptResult>& results)
         EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

private:
    CTxMemPool& m_pool;
    CCoinsViewCache m_view;
    CCoinsViewMemPool m_viewmempool;
    CCoinsView m_dummy;

    CChainState& m_active_chainstate;

    // The package limits in effect at the time of invocation.
    const size_t m_limit_ancestors;
    const size_t m_limit_ancestor_size;
    // These may be modified while evaluating a transaction (eg to account for
    // in-mempool conflicts; see below).
    size_t m_limit_descendants;
    size_t m_limit_descendant_size;
};

bool MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransactionRef& ptx = ws.m_ptx;
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    // Copy/alias what we need out of args
    const int64_t nAcceptTime = args.m_accept_time;
    std::vector<COutPoint>& coins_to_uncache = args.m_coins_to_uncache;

    // Alias what we need out of ws
    TxValidationState& state = ws.m_state;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    if (!CheckTransaction(tx, state)) {
        return false; // state filled in by CheckTransaction
    }
    // Time (prevent mempool memory exhaustion attack)
    // moved from CheckTransaction() to here, because it makes no sense to make GetAdjustedTime() a part of the consensus rules - user can set his clock to whatever he wishes.
    if (tx.nTime > GetAdjustedTime() + (IsProtocolV09(GetAdjustedTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9))
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "timestamp-too-far");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase() || tx.IsCoinStake())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason))
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);

    // Do not work on transactions that are too small.
    // A transaction with 1 segwit input and 1 P2WPHK output has non-witness size of 82 bytes.
    // Transactions smaller than this are not relayed to mitigate CVE-2017-12842 by not relaying
    // 64-byte transactions.
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) < MIN_STANDARD_TX_NONWITNESS_SIZE)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(m_active_chainstate.m_chain.Tip(), tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final");

    if (m_pool.exists(GenTxid::Wtxid(tx.GetWitnessHash()))) {
        // Exact transaction already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    } else if (m_pool.exists(GenTxid::Txid(tx.GetHash()))) {
        // Transaction with the same non-witness data but different witness (same txid, different
        // wtxid) already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-same-nonwitness-data-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin)
    {
        const CTransaction* ptxConflicting = m_pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            // Disable replacement feature for now
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "txn-mempool-conflict");
        }
    }

    LockPoints lp;
    m_view.SetBackend(m_viewmempool);

    const CCoinsViewCache& coins_cache = m_active_chainstate.CoinsTip();
    // do all inputs exist?
    for (const CTxIn& txin : tx.vin) {
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be removed
        // later (via coins_to_uncache) if this tx turns out to be invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.vout.size(); out++) {
                // Optimistically just do efficient check of cache for outputs
                if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
                }
            }
            // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
        }
    }

    // This is const, but calls into the back end CoinsViews. The CCoinsViewDB at the bottom of the
    // hierarchy brings the best block into scope. See CCoinsViewDB::GetBestBlock().
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being added
    // to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    assert(m_active_chainstate.m_blockman.LookupBlockIndex(m_view.GetBestBlock()) == m_active_chainstate.m_chain.Tip());

    // Only accept BIP68 sequence locked transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    // Pass in m_view which has all of the relevant inputs cached. Note that, since m_view's
    // backend was removed, it no longer pulls coins from the mempool.
    if (!CheckSequenceLocks(m_active_chainstate.m_chain.Tip(), m_view, tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");

    // The mempool holds txs for the next block, so pass height+1 to CheckTxInputs
    if (!Consensus::CheckTxInputs(tx, state, m_view, m_active_chainstate.m_chain.Height() + 1, ws.m_base_fees, Params().GetConsensus(), tx.nTime ? tx.nTime : GetAdjustedTime())) {
        return false; // state filled in by CheckTxInputs
    }

    if (ws.m_base_fees < GetMinFee(tx, tx.nTime ? tx.nTime : GetAdjustedTime()))
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "fee is below minimum");
    // Check for non-standard pay-to-script-hash in inputs
    if (fRequireStandard && !AreInputsStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs");
    }

    // Check for non-standard witnesses.
    if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, m_view))
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-witness-nonstandard");

    int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);

    // ws.m_modified_fees includes any fee deltas from PrioritiseTransaction
    ws.m_modified_fees = ws.m_base_fees;
    m_pool.ApplyDelta(hash, ws.m_modified_fees);

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure COINBASE_MATURITY is still met.
    bool fSpendsCoinbase = false;
    for (const CTxIn &txin : tx.vin) {
        const Coin &coin = m_view.AccessCoin(txin.prevout);
        if (coin.IsCoinBase() || coin.IsCoinStake()) {
            fSpendsCoinbase = true;
            break;
        }
    }

    entry.reset(new CTxMemPoolEntry(ptx, ws.m_base_fees, nAcceptTime, m_active_chainstate.m_chain.Height(),
            fSpendsCoinbase, nSigOpsCost, lp));
    ws.m_vsize = entry->GetTxSize();

    if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops",
                strprintf("%d", nSigOpsCost));


    std::string errString;
    if (!m_pool.CalculateMemPoolAncestors(*entry, ws.m_ancestors, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants, m_limit_descendant_size, errString)) {
        ws.m_ancestors.clear();
        // If CalculateMemPoolAncestors fails second time, we want the original error string.
        std::string dummy_err_string;
        // Contracting/payment channels CPFP carve-out:
        // If the new transaction is relatively small (up to 40k weight)
        // and has at most one ancestor (ie ancestor limit of 2, including
        // the new transaction), allow it if its parent has exactly the
        // descendant limit descendants.
        //
        // This allows protocols which rely on distrusting counterparties
        // being able to broadcast descendants of an unconfirmed transaction
        // to be secure by simply only having two immediately-spendable
        // outputs - one for each counterparty. For more info on the uses for
        // this, see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-November/016518.html
        if (ws.m_vsize > EXTRA_DESCENDANT_TX_SIZE_LIMIT ||
                !m_pool.CalculateMemPoolAncestors(*entry, ws.m_ancestors, 2, m_limit_ancestor_size, m_limit_descendants + 1, m_limit_descendant_size + EXTRA_DESCENDANT_TX_SIZE_LIMIT, dummy_err_string)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-long-mempool-chain", errString);
        }
    }

    return true;
}

bool MemPoolAccept::PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                                         PackageValidationState& package_state)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    // CheckPackageLimits expects the package transactions to not already be in the mempool.
    assert(std::all_of(txns.cbegin(), txns.cend(), [this](const auto& tx)
                       { return !m_pool.exists(GenTxid::Txid(tx->GetHash()));}));

    std::string err_string;
    if (!m_pool.CheckPackageLimits(txns, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants,
                                   m_limit_descendant_size, err_string)) {
        // This is a package-wide error, separate from an individual transaction error.
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-mempool-limits", err_string);
    }
   return true;
}

bool MemPoolAccept::PolicyScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    TxValidationState& state = ws.m_state;

    unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // peercoin: if transaction is after version 0.8 fork, verify SCRIPT_VERIFY_LOW_S
    // ppcTODO move back to policy.h after 0.8 is active
    //if (IsBTC16BIPsEnabled(tx.nTime))
    //    scriptVerifyFlags &= SCRIPT_VERIFY_LOW_S;

    // peercoin allow taproot after fork
    //if (IsProtocolV12(tx.nTime))
    //    scriptVerifyFlags &= SCRIPT_VERIFY_TAPROOT;

    // Check input scripts and signatures.
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false, ws.m_precomputed_txdata)) {
        // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
        // need to turn both off, and compare against just turning off CLEANSTACK
        // to see if the failure is specifically due to witness validation.
        TxValidationState state_dummy; // Want reported failures to be from first CheckInputScripts
        if (!tx.HasWitness() && CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, ws.m_precomputed_txdata) &&
                !CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, ws.m_precomputed_txdata)) {
            // Only the witness is missing, so the transaction itself may be fine.
            state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED,
                    state.GetRejectReason(), state.GetDebugMessage());
        }
        return false; // state filled in by CheckInputScripts
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;
    const CChainParams& chainparams = args.m_chainparams;

    // Check again against the current block tip's script verification
    // flags to cache our script execution flags. This is, of course,
    // useless if the next block has different script flags from the
    // previous one, but because the cache tracks script flags for us it
    // will auto-invalidate and we'll just have a few blocks of extra
    // misses on soft-fork activation.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain
    // CHECKSIG NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(m_active_chainstate.m_chain.Tip(), chainparams.GetConsensus());
    if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool, currentBlockScriptVerifyFlags,
                                        ws.m_precomputed_txdata, m_active_chainstate.CoinsTip())) {
        LogPrintf("BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s\n", hash.ToString(), state.ToString());
        return Assume(false);
    }

    return true;
}

bool MemPoolAccept::Finalize(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const uint256& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;
    const bool bypass_limits = args.m_bypass_limits;

    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    // Store transaction in memory
    m_pool.addUnchecked(*entry, ws.m_ancestors);

    // trim mempool and check if tx was trimmed
    // If we are validating a package, don't trim here because we could evict a previous transaction
    // in the package. LimitMempoolSize() should be called at the very end to make sure the mempool
    // is still within limits and package submission happens atomically.
    if (!args.m_package_submission && !bypass_limits) {
        LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip(), gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, std::chrono::hours{gArgs.GetIntArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
        if (!m_pool.exists(GenTxid::Txid(hash)))
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
    }
    return true;
}

bool MemPoolAccept::SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces,
                                  PackageValidationState& package_state,
                                  std::map<const uint256, const MempoolAcceptResult>& results)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    // Sanity check: none of the transactions should be in the mempool, and none of the transactions
    // should have a same-txid-different-witness equivalent in the mempool.
    assert(std::all_of(workspaces.cbegin(), workspaces.cend(), [this](const auto& ws){
        return !m_pool.exists(GenTxid::Txid(ws.m_ptx->GetHash())); }));

    bool all_submitted = true;
    // ConsensusScriptChecks adds to the script cache and is therefore consensus-critical;
    // CheckInputsFromMempoolAndCache asserts that transactions only spend coins available from the
    // mempool or UTXO set. Submit each transaction to the mempool immediately after calling
    // ConsensusScriptChecks to make the outputs available for subsequent transactions.
    for (Workspace& ws : workspaces) {
        if (!ConsensusScriptChecks(args, ws)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since PolicyScriptChecks() passed, this should never fail.
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! PolicyScriptChecks succeeded but ConsensusScriptChecks failed: %s",
                                            ws.m_ptx->GetHash().ToString()));
        }

        // Re-calculate mempool ancestors to call addUnchecked(). They may have changed since the
        // last calculation done in PreChecks, since package ancestors have already been submitted.
        std::string unused_err_string;
        if(!m_pool.CalculateMemPoolAncestors(*ws.m_entry, ws.m_ancestors, m_limit_ancestors,
                                             m_limit_ancestor_size, m_limit_descendants,
                                             m_limit_descendant_size, unused_err_string)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since PreChecks() and PackageMempoolChecks() both enforce limits, this should never fail.
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! Mempool ancestors or descendants were underestimated: %s",
                                            ws.m_ptx->GetHash().ToString()));
        }
        // If we call LimitMempoolSize() for each individual Finalize(), the mempool will not take
        // the transaction's descendant feerate into account because it hasn't seen them yet. Also,
        // we risk evicting a transaction that a subsequent package transaction depends on. Instead,
        // allow the mempool to temporarily bypass limits, the maximum package size) while
        // submitting transactions individually and then trim at the very end.
        if (!Finalize(args, ws)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since LimitMempoolSize() won't be called, this should never fail.
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! Adding to mempool failed: %s", ws.m_ptx->GetHash().ToString()));
        }
    }

    // It may or may not be the case that all the transactions made it into the mempool. Regardless,
    // make sure we haven't exceeded max mempool size.
    LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip(),
                     gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
                     std::chrono::hours{gArgs.GetIntArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});

    // Find the wtxids of the transactions that made it into the mempool. Allow partial submission,
    // but don't report success unless they all made it into the mempool.
    for (Workspace& ws : workspaces) {
        if (m_pool.exists(GenTxid::Wtxid(ws.m_ptx->GetWitnessHash()))) {
            results.emplace(ws.m_ptx->GetWitnessHash(),
                MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees));
            GetMainSignals().TransactionAddedToMempool(ws.m_ptx, m_pool.GetAndIncrementSequence());
        } else {
            all_submitted = false;
            ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
        }
    }
    return all_submitted;
}

MempoolAcceptResult MemPoolAccept::AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    LOCK(m_pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())

    Workspace ws(ptx);

    if (!PreChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    // Perform the inexpensive checks first and avoid hashing and signature verification unless
    // those checks pass, to mitigate CPU exhaustion denial-of-service attacks.
    if (!PolicyScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    if (!ConsensusScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    // Tx was accepted, but not added
    if (args.m_test_accept) {
        return MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees);
    }

    if (!Finalize(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    GetMainSignals().TransactionAddedToMempool(ptx, m_pool.GetAndIncrementSequence());

    return MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees);
}

PackageMempoolAcceptResult MemPoolAccept::AcceptMultipleTransactions(const std::vector<CTransactionRef>& txns, ATMPArgs& args)
{
    AssertLockHeld(cs_main);

    // These context-free package limits can be done before taking the mempool lock.
    PackageValidationState package_state;
    if (!CheckPackage(txns, package_state)) return PackageMempoolAcceptResult(package_state, {});

    std::vector<Workspace> workspaces{};
    workspaces.reserve(txns.size());
    std::transform(txns.cbegin(), txns.cend(), std::back_inserter(workspaces),
                   [](const auto& tx) { return Workspace(tx); });
    std::map<const uint256, const MempoolAcceptResult> results;

    LOCK(m_pool.cs);

    // Do all PreChecks first and fail fast to avoid running expensive script checks when unnecessary.
    for (Workspace& ws : workspaces) {
        if (!PreChecks(args, ws)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }
        // Make the coins created by this transaction available for subsequent transactions in the
        // package to spend. Since we already checked conflicts in the package and we don't allow
        // replacements, we don't need to track the coins spent. Note that this logic will need to be
        // updated if package replace-by-fee is allowed in the future.
        assert(!args.m_allow_bip125_replacement);
        m_viewmempool.PackageAddTransaction(ws.m_ptx);
    }

    // Apply package mempool ancestor/descendant limits. Skip if there is only one transaction,
    // because it's unnecessary. Also, CPFP carve out can increase the limit for individual
    // transactions, but this exemption is not extended to packages in CheckPackageLimits().
    std::string err_string;
    if (txns.size() > 1 && !PackageMempoolChecks(txns, package_state)) {
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    for (Workspace& ws : workspaces) {
        if (!PolicyScriptChecks(args, ws)) {
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }
        if (args.m_test_accept) {
            // When test_accept=true, transactions that pass PolicyScriptChecks are valid because there are
            // no further mempool checks (passing PolicyScriptChecks implies passing ConsensusScriptChecks).
            results.emplace(ws.m_ptx->GetWitnessHash(),
                            MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions),
                                                         ws.m_vsize, ws.m_base_fees));
        }
    }

    if (args.m_test_accept) return PackageMempoolAcceptResult(package_state, std::move(results));

    if (!SubmitPackage(args, workspaces, package_state, results)) {
        // PackageValidationState filled in by SubmitPackage().
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    return PackageMempoolAcceptResult(package_state, std::move(results));
}

PackageMempoolAcceptResult MemPoolAccept::AcceptPackage(const Package& package, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    PackageValidationState package_state;

    // Check that the package is well-formed. If it isn't, we won't try to validate any of the
    // transactions and thus won't return any MempoolAcceptResults, just a package-wide error.

    // Context-free package checks.
    if (!CheckPackage(package, package_state)) return PackageMempoolAcceptResult(package_state, {});

    // All transactions in the package must be a parent of the last transaction. This is just an
    // opportunity for us to fail fast on a context-free check without taking the mempool lock.
    if (!IsChildWithParents(package)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-child-with-parents");
        return PackageMempoolAcceptResult(package_state, {});
    }

    // IsChildWithParents() guarantees the package is > 1 transactions.
    assert(package.size() > 1);
    // The package must be 1 child with all of its unconfirmed parents. The package is expected to
    // be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> unconfirmed_parent_txids;
    std::transform(package.cbegin(), package.cend() - 1,
                   std::inserter(unconfirmed_parent_txids, unconfirmed_parent_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    // All child inputs must refer to a preceding package transaction or a confirmed UTXO. The only
    // way to verify this is to look up the child's inputs in our current coins view (not including
    // mempool), and enforce that all parents not present in the package be available at chain tip.
    // Since this check can bring new coins into the coins cache, keep track of these coins and
    // uncache them if we don't end up submitting this package to the mempool.
    const CCoinsViewCache& coins_tip_cache = m_active_chainstate.CoinsTip();
    for (const auto& input : child->vin) {
        if (!coins_tip_cache.HaveCoinInCache(input.prevout)) {
            args.m_coins_to_uncache.push_back(input.prevout);
        }
    }
    // Using the MemPoolAccept m_view cache allows us to look up these same coins faster later.
    // This should be connecting directly to CoinsTip, not to m_viewmempool, because we specifically
    // require inputs to be confirmed if they aren't in the package.
    m_view.SetBackend(m_active_chainstate.CoinsTip());
    const auto package_or_confirmed = [this, &unconfirmed_parent_txids](const auto& input) {
         return unconfirmed_parent_txids.count(input.prevout.hash) > 0 || m_view.HaveCoin(input.prevout);
    };
    if (!std::all_of(child->vin.cbegin(), child->vin.cend(), package_or_confirmed)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-child-with-unconfirmed-parents");
        return PackageMempoolAcceptResult(package_state, {});
    }
    // Protect against bugs where we pull more inputs from disk that miss being added to
    // coins_to_uncache. The backend will be connected again when needed in PreChecks.
    m_view.SetBackend(m_dummy);

    LOCK(m_pool.cs);
    std::map<const uint256, const MempoolAcceptResult> results;
    // Node operators are free to set their mempool policies however they please, nodes may receive
    // transactions in different orders, and malicious counterparties may try to take advantage of
    // policy differences to pin or delay propagation of transactions. As such, it's possible for
    // some package transaction(s) to already be in the mempool, and we don't want to reject the
    // entire package in that case (as that could be a censorship vector). De-duplicate the
    // transactions that are already in the mempool, and only call AcceptMultipleTransactions() with
    // the new transactions. This ensures we don't double-count transaction counts and sizes when
    // checking ancestor/descendant limits, or double-count transaction fees for fee-related policy.
    std::vector<CTransactionRef> txns_new;
    for (const auto& tx : package) {
        const auto& wtxid = tx->GetWitnessHash();
        const auto& txid = tx->GetHash();
        // There are 3 possibilities: already in mempool, same-txid-diff-wtxid already in mempool,
        // or not in mempool. An already confirmed tx is treated as one not in mempool, because all
        // we know is that the inputs aren't available.
        if (m_pool.exists(GenTxid::Wtxid(wtxid))) {
            // Exact transaction already exists in the mempool.
            auto iter = m_pool.GetIter(txid);
            assert(iter != std::nullopt);
            results.emplace(wtxid, MempoolAcceptResult::MempoolTx(iter.value()->GetTxSize(), iter.value()->GetFee()));
        } else if (m_pool.exists(GenTxid::Txid(txid))) {
            // Transaction with the same non-witness data but different witness (same txid,
            // different wtxid) already exists in the mempool.
            //
            // We don't allow replacement transactions right now, so just swap the package
            // transaction for the mempool one. Note that we are ignoring the validity of the
            // package transaction passed in.
            // TODO: allow witness replacement in packages.
            auto iter = m_pool.GetIter(txid);
            assert(iter != std::nullopt);
            // Provide the wtxid of the mempool tx so that the caller can look it up in the mempool.
            results.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(iter.value()->GetTx().GetWitnessHash()));
        } else {
            // Transaction does not already exist in the mempool.
            txns_new.push_back(tx);
        }
    }

    // Nothing to do if the entire package has already been submitted.
    if (txns_new.empty()) return PackageMempoolAcceptResult(package_state, std::move(results));
    // Validate the (deduplicated) transactions as a package.
    auto submission_result = AcceptMultipleTransactions(txns_new, args);
    // Include already-in-mempool transaction results in the final result.
    for (const auto& [wtxid, mempoolaccept_res] : results) {
        submission_result.m_tx_results.emplace(wtxid, mempoolaccept_res);
    }
    return submission_result;
}

} // anon namespace

MempoolAcceptResult AcceptToMemoryPool(CChainState& active_chainstate, const CTransactionRef& tx,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    const CChainParams& chainparams{active_chainstate.m_params};
    assert(active_chainstate.GetMempool() != nullptr);
    CTxMemPool& pool{*active_chainstate.GetMempool()};

    std::vector<COutPoint> coins_to_uncache;
    auto args = MemPoolAccept::ATMPArgs::SingleAccept(chainparams, accept_time, bypass_limits, coins_to_uncache, test_accept);
    const MempoolAcceptResult result = MemPoolAccept(pool, active_chainstate).AcceptSingleTransaction(tx, args);
    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        // Remove coins that were not present in the coins cache before calling
        // AcceptSingleTransaction(); this is to prevent memory DoS in case we receive a large
        // number of invalid transactions that attempt to overrun the in-memory coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint& hashTx : coins_to_uncache)
            active_chainstate.CoinsTip().Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

PackageMempoolAcceptResult ProcessNewPackage(CChainState& active_chainstate, CTxMemPool& pool,
                                                   const Package& package, bool test_accept)
{
    AssertLockHeld(cs_main);
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));

    std::vector<COutPoint> coins_to_uncache;
    const CChainParams& chainparams = Params();
    const auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        if (test_accept) {
            auto args = MemPoolAccept::ATMPArgs::PackageTestAccept(chainparams, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate).AcceptMultipleTransactions(package, args);
        } else {
            auto args = MemPoolAccept::ATMPArgs::PackageChildWithParents(chainparams, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate).AcceptPackage(package, args);
        }
    }();

    // Uncache coins pertaining to transactions that were not submitted to the mempool.
    if (test_accept || result.m_state.IsInvalid()) {
        for (const COutPoint& hashTx : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(hashTx);
        }
    }
    // Ensure the coins cache is still within limits.
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

int64_t GetProofOfWorkReward(unsigned int nBits, uint32_t nTime)
{
    CBigNum bnSubsidyLimit = MAX_MINT_PROOF_OF_WORK;
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnTargetLimit(Params().GetConsensus().powLimit);
    bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

    // peercoin: subsidy is cut in half every 16x multiply of difficulty
    // A reasonably continuous curve is used to avoid shock to market
    // (nSubsidyLimit / nSubsidy) ** 4 == bnProofOfWorkLimit / bnTarget
    CBigNum bnLowerBound = CENT;
    CBigNum bnUpperBound = bnSubsidyLimit;
    while (bnLowerBound + CENT <= bnUpperBound)
    {
        CBigNum bnMidValue = (bnLowerBound + bnUpperBound) / 2;
        if (gArgs.GetBoolArg("-printcreation", false))
            LogPrintf("%s: lower=%lld upper=%lld mid=%lld\n", __func__, bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnTargetLimit > bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnTarget)
            bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }

    int64_t nSubsidy = bnUpperBound.getuint64();
    nSubsidy = (nSubsidy / CENT) * CENT;

    nSubsidy = std::min(nSubsidy, IsProtocolV10(nTime) ? MAX_MINT_PROOF_OF_WORK_V10 : MAX_MINT_PROOF_OF_WORK);

    if (gArgs.GetBoolArg("-printcreation", false))
        LogPrintf("%s: create=%s nBits=0x%08x nSubsidy=%lld\n", __func__, FormatMoney(nSubsidy), nBits, nSubsidy);

    return nSubsidy;
}

// peercoin: miner's coin stake is rewarded based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, uint32_t nTime, uint64_t nMoneySupply)
{
    static int64_t nRewardCoinYear = CENT;  // creation amount per coin-year
    int64_t nSubsidy = nCoinAge * 33 / (365 * 33 + 8) * nRewardCoinYear;

    if (IsProtocolV09(nTime)) {
        // rfc18
        // YearlyBlocks = ((365 * 33 + 8) / 33) * 1440 / 10
        // some efforts not to lose precision
        CBigNum bnInflationAdjustment = nMoneySupply;
        bnInflationAdjustment *= 25 * 33;
        bnInflationAdjustment /= 10000 * 144;
        bnInflationAdjustment /= (365 * 33 + 8);

        uint64_t nInflationAdjustment = bnInflationAdjustment.getuint64();
        uint64_t nSubsidyNew = (nSubsidy * 3) + nInflationAdjustment;

        if (gArgs.GetBoolArg("-printcreation", false))
            LogPrintf("%s: money supply %ld, inflation adjustment %f, old subsidy %ld, new subsidy %ld\n", __func__, nMoneySupply, nInflationAdjustment/1000000.0, nSubsidy, nSubsidyNew);

        nSubsidy = nSubsidyNew;
        }

    if (gArgs.GetBoolArg("-printcreation", false))
        LogPrintf("%s: create=%s nCoinAge=%lld\n", __func__, FormatMoney(nSubsidy), nCoinAge);
    return nSubsidy;
}

CoinsViews::CoinsViews(
    std::string ldb_name,
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe) : m_dbview(
                            gArgs.GetDataDirNet() / ldb_name, cache_size_bytes, in_memory, should_wipe),
                        m_catcherview(&m_dbview) {}

void CoinsViews::InitCache()
{
    AssertLockHeld(::cs_main);
    m_cacheview = std::make_unique<CCoinsViewCache>(&m_catcherview);
}

CChainState::CChainState(
    CTxMemPool* mempool,
    BlockManager& blockman,
    ChainstateManager& chainman,
    std::optional<uint256> from_snapshot_blockhash)
    : m_mempool(mempool),
      m_blockman(blockman),
      m_params(::Params()),
      m_chainman(chainman),
      m_from_snapshot_blockhash(from_snapshot_blockhash) {}

void CChainState::InitCoinsDB(
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe,
    std::string leveldb_name)
{
    if (m_from_snapshot_blockhash) {
        leveldb_name += "_" + m_from_snapshot_blockhash->ToString();
    }

    m_coins_views = std::make_unique<CoinsViews>(
        leveldb_name, cache_size_bytes, in_memory, should_wipe);
}

void CChainState::InitCoinsCache(size_t cache_size_bytes)
{
    AssertLockHeld(::cs_main);
    assert(m_coins_views != nullptr);
    m_coinstip_cache_size_bytes = cache_size_bytes;
    m_coins_views->InitCache();
}

// Note that though this is marked const, we may end up modifying `m_cached_finished_ibd`, which
// is a performance-related implementation detail. This function must be marked
// `const` so that `CValidationInterface` clients (which are given a `const CChainState*`)
// can call it.
//
bool CChainState::IsInitialBlockDownload() const
{
    // Optimization: pre-test latch before taking the lock.
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (m_chain.Tip() == nullptr)
        return true;
    if (m_chain.Tip()->nChainTrust < nMinimumChainWork)
        return true;
    if (m_chain.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    return false;
}


void AlertNotify(const std::string& strMessage, bool fUpdateUI)
{
    if (fUpdateUI)
        uiInterface.NotifyAlertChanged(uint256(), CT_UPDATED); // peercoin: we are using arguments that will have no effects in updateAlert()
#if HAVE_SYSTEM
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
#endif
}

void CChainState::CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);

    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload()) {
        return;
    }

    if (m_chainman.m_best_invalid && m_chainman.m_best_invalid->nChainTrust > m_chain.Tip()->nChainTrust + (GetBlockTrust(*m_chain.Tip()) * 6)) {
        LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
        SetfLargeWorkInvalidChainFound(true);
    } else {
        SetfLargeWorkInvalidChainFound(false);
    }
}

// Called both upon regular invalid block discovery *and* InvalidateBlock
void CChainState::InvalidChainFound(CBlockIndex* pindexNew)
{
    AssertLockHeld(cs_main);
    if (!m_chainman.m_best_invalid || pindexNew->nChainTrust > m_chainman.m_best_invalid->nChainTrust) {
        m_chainman.m_best_invalid = pindexNew;
    }
    if (pindexBestHeader != nullptr && pindexBestHeader->GetAncestor(pindexNew->nHeight) == pindexNew) {
        pindexBestHeader = m_chain.Tip();
    }

    LogPrintf("%s: invalid block=%s  height=%d  log2_trust=%.8g  moneysupply=%s  date=%s  moneysupply=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainTrust.getdouble())/log(2.0), 
      FormatMoney(m_chain.Tip()->nMoneySupply),
      FormatISO8601DateTime(pindexNew->GetBlockTime()),
      FormatMoney(pindexNew->nMoneySupply));
    CBlockIndex *tip = m_chain.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_trust=%.8g  moneysupply=%s  date=%s  moneysupply=%s\n", __func__,
      tip->GetBlockHash().ToString(), m_chain.Height(), log(tip->nChainTrust.getdouble())/log(2.0),
      FormatMoney(tip->nMoneySupply),
      FormatISO8601DateTime(tip->GetBlockTime()), FormatMoney(pindexNew->nMoneySupply));
    CheckForkWarningConditions();
}

// Same as InvalidChainFound, above, except not called directly from InvalidateBlock,
// which does its own setBlockIndexCandidates management.
void CChainState::InvalidBlockFound(CBlockIndex* pindex, const BlockValidationState& state)
{
    AssertLockHeld(cs_main);
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_chainman.m_failed_blocks.insert(pindex);
        m_blockman.m_dirty_blockindex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight, bool skipZeroValue)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight, false, skipZeroValue);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

static CuckooCache::cache<uint256, SignatureCacheHasher> g_scriptExecutionCache;
static CSHA256 g_scriptExecutionCacheHasher;

void InitScriptExecutionCache() {
    // Setup the salted hasher
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // just write our 32-byte entropy twice to fill the 64 bytes.
    g_scriptExecutionCacheHasher.Write(nonce.begin(), 32);
    g_scriptExecutionCacheHasher.Write(nonce.begin(), 32);
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetIntArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = g_scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck>* pvChecks)
{
    if (tx.IsCoinBase()) return true;

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    CSHA256 hasher = g_scriptExecutionCacheHasher;
    hasher.Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
    if (g_scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
        return true;
    }

    if (!txdata.m_spent_outputs_ready) {
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(tx.vin.size());

        for (const auto& txin : tx.vin) {
            const COutPoint& prevout = txin.prevout;
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());
            spent_outputs.emplace_back(coin.out);
        }
        txdata.Init(tx, std::move(spent_outputs));
    }
    assert(txdata.m_spent_outputs.size() == tx.vin.size());

    for (unsigned int i = 0; i < tx.vin.size(); i++) {

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(txdata.m_spent_outputs[i], tx, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->push_back(CScriptCheck());
            check.swap(pvChecks->back());
        } else if (!check()) {
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                // Check whether the failure was caused by a
                // non-mandatory script verification check, such as
                // non-standard DER encodings or non-null dummy
                // arguments; if so, ensure we return NOT_STANDARD
                // instead of CONSENSUS to avoid downstream users
                // splitting the network between upgraded and
                // non-upgraded nodes by banning CONSENSUS-failing
                // data providers.
                CScriptCheck check2(txdata.m_spent_outputs[i], tx, i,
                        flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                if (check2())
                    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
            }
            // MANDATORY flag failures correspond to
            // TxValidationResult::TX_CONSENSUS. Because CONSENSUS
            // failures are the most serious case of validation
            // failures, we may need to consider using
            // RECENT_CONSENSUS_CHANGE for any script failure that
            // could be due to non-upgraded nodes which we may want to
            // support, to avoid splitting the network (but this
            // depends on the details of how net_processing handles
            // such errors).
            return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
        }
    }

    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        g_scriptExecutionCache.insert(hashCacheEntry);
    }

    return true;
}

bool AbortNode(BlockValidationState& state, const std::string& strMessage, const bilingual_str& userMessage)
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
            undo.fCoinStake = alternate.fCoinStake; // peercoin
            undo.nTime = alternate.nTime;           // peercoin
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // If the coin already exists as an unspent coin in the cache, then the
    // possible_overwrite parameter to AddCoin must be set to true. We have
    // already checked whether an unspent coin exists above using HaveCoin, so
    // we don't need to guess. When fClean is false, an unspent coin already
    // existed and it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean, false);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    AssertLockHeld(::cs_main);
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();
        bool is_coinstake = tx.IsCoinStake();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                if (IsProtocolV12(pindex) && !tx.vout[o].nValue)
                    continue;
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase || is_coinstake != coin.fCoinStake) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j > 0;) {
                --j;
                const COutPoint& out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void StartScriptCheckWorkerThreads(int threads_num)
{
    scriptcheckqueue.StartWorkerThreads(threads_num);
}

void StopScriptCheckWorkerThreads()
{
    scriptcheckqueue.StopWorkerThreads();
}

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams)
{
    unsigned int flags = SCRIPT_VERIFY_NONE;

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet), so for simplicity, always leave P2SH
    // on except for the one violating block.
    if (consensusparams.BIP16Exception.IsNull() || // no bip16 exception on this chain
        pindex->phashBlock == nullptr || // this is a new candidate block, eg from TestBlockValidity()
        *pindex->phashBlock != consensusparams.BIP16Exception) // this block isn't the historical exception
    {
        // Enforce WITNESS rules whenever P2SH is in effect
        flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    }

    // Enforce the DERSIG (BIP66) rule
    if (pindex->pprev && IsBTC16BIPsEnabled(pindex->pprev->nTime)) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Enforce CHECKLOCKTIMEVERIFY (BIP65)
    if (IsProtocolV06(pindex->pprev)) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Enforce BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY)
    // Enforce BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (pindex->pprev && IsBTC16BIPsEnabled(pindex->pprev->nTime)) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY;
    }

    // Enforce Taproot (BIP340-BIP342)
    if (pindex->pprev && IsProtocolV12(pindex->pprev)) {
        flags |= SCRIPT_VERIFY_TAPROOT;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

// These checks can only be done when all previous block have been added.
bool PeercoinContextualBlockChecks(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex, bool fJustCheck, CChainState& chainstate)
{
    uint256 hashProofOfStake = uint256();
    // peercoin: verify hash target and signature of coinstake tx
    if (block.IsProofOfStake() && !CheckProofOfStake(state, pindex->pprev, block.vtx[1], block.nBits, hashProofOfStake, block.vtx[1]->nTime ? block.vtx[1]->nTime : block.nTime, chainstate)) {
        LogPrintf("WARNING: %s: check proof-of-stake failed for block %s\n", __func__, block.GetHash().ToString());
        return false; // do not error here as we expect this during initial block download
    }

    // peercoin: check for duplicity of stake
    if (block.IsProofOfStake()) {
        std::pair<COutPoint, unsigned int> proofOfStake = block.GetProofOfStake();
        if (pindex->IsProofOfStake() && proofOfStake.first == pindex->prevoutStake) {
            LogPrintf("WARNING: %s: duplicate proof-of-stake in block %s, invalidating tip\n", __func__, block.GetHash().ToString());
            chainstate.InvalidateBlock(state, pindex);
            return error("ConnectBlock() : Duplicate coinstake found");
        } else if (setStakeSeen.count(proofOfStake)) {
            LogPrintf("WARNING: %s: duplicate proof-of-stake in block %s\n", __func__, block.GetHash().ToString());
            return error("ConnectBlock() : Duplicate coinstake found");
        }
    }

    // peercoin: compute stake entropy bit for stake modifier
    unsigned int nEntropyBit = GetStakeEntropyBit(block);

    // peercoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindex, nStakeModifier, fGeneratedStakeModifier, chainstate))
        return error("ConnectBlock() : ComputeNextStakeModifier() failed");

    // compute nStakeModifierChecksum begin
    unsigned int nFlagsBackup      = pindex->nFlags;
    uint64_t nStakeModifierBackup  = pindex->nStakeModifier;
    uint256 hashProofOfStakeBackup = pindex->hashProofOfStake;

    // set necessary pindex fields
    if (!pindex->SetStakeEntropyBit(nEntropyBit))
        return error("ConnectBlock() : SetStakeEntropyBit() failed");
    pindex->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindex->hashProofOfStake = hashProofOfStake;

    unsigned int nStakeModifierChecksum = GetStakeModifierChecksum(pindex);

    // undo pindex fields
    pindex->nFlags           = nFlagsBackup;
    pindex->nStakeModifier   = nStakeModifierBackup;
    pindex->hashProofOfStake = hashProofOfStakeBackup;
    // compute nStakeModifierChecksum end

    if (!CheckStakeModifierCheckpoints(pindex->nHeight, nStakeModifierChecksum))
        return error("ConnectBlock() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016llx", pindex->nHeight, nStakeModifier);

    if (fJustCheck)
        return true;

    // write everything to index
    if (block.IsProofOfStake())
    {
        pindex->prevoutStake = block.vtx[1]->vin[0].prevout;
        pindex->nStakeTime = block.vtx[1]->nTime;
        pindex->hashProofOfStake = hashProofOfStake;
        setStakeSeen.insert(std::make_pair(pindex->prevoutStake, pindex->nTime));
    }
    if (!pindex->SetStakeEntropyBit(nEntropyBit))
        return error("ConnectBlock() : SetStakeEntropyBit() failed");
    pindex->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindex->nStakeModifierChecksum = nStakeModifierChecksum;
    chainstate.m_blockman.m_dirty_blockindex.insert(pindex); // queue a write to disk

    return true;
}

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                               CCoinsViewCache& view, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);

    uint256 block_hash{block.GetHash()};
    assert(*pindex->phashBlock == block_hash);

    int64_t nTimeStart = GetTimeMicros();

    if (pindex->nStakeModifier == 0 && pindex->nStakeModifierChecksum == 0 && !PeercoinContextualBlockChecks(block, state, pindex, fJustCheck, m_chainman.ActiveChainstate()))
        return error("%s: failed PoS check %s", __func__, state.ToString());

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see NeedsRedownload()
    // for one approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, m_params.GetConsensus(), !fJustCheck, !fJustCheck)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    nBlocksTotal++;

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block_hash == m_params.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = m_blockman.m_block_index.find(hashAssumeValid);
        if (it != m_blockman.m_block_index.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainTrust >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // Script verification is skipped when connecting blocks under the
                // assumevalid block. Assuming the assumevalid block is valid this
                // is safe because block merkle hashes are still computed and checked,
                // Of course, if an assumed valid block is invalid due to false scriptSigs
                // this optimization would allow an invalid chain to be accepted.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, m_params.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30, CVE-2012-1909, and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock); // Enforce on CreateNewBlock invocations which don't have a hash.

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried it's no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // There is no potential to create a duplicate coinbase at block 209,921
    // because this is still before the BIP34 height and so explicit BIP30
    // checking is still active.

    // The final case is block 176,684 which has an indicated height of
    // 490,897. Unfortunately, this issue was not discovered until about 2 weeks
    // before block 490,897 so there was not much opportunity to address this
    // case other than to carefully analyze it and determine it would not be a
    // problem. Block 490,897 was, in fact, mined with a different coinbase than
    // block 176,684, but it is important to note that even if it hadn't been or
    // is remined on an alternate fork with a duplicate coinbase, we would still
    // not run into a BIP30 violation.  This is because the coinbase for 176,684
    // is spent in block 185,956 in transaction
    // d4f7fbbf92f4a3014a230b2dc70b8058d02eb36ac06b4a0736d9d60eaa9e8781.  This
    // spending transaction can't be duplicated because it also spends coinbase
    // 0328dd85c331237f18e781d692c92de57649529bd5edf1d01036daea32ffde29.  This
    // coinbase has an indicated height of over 4.2 billion, and wouldn't be
    // duplicatable until that height, and it's currently impossible to create a
    // chain that long. Nevertheless we may wish to consider a future soft fork
    // which retroactively prevents block 490,897 from creating a duplicate
    // coinbase. The two historical BIP30 violations often provide a confusing
    // edge case when manipulating the UTXO and it would be simpler not to have
    // another edge case to deal with.

    // testnet3 has no blocks before the BIP34 height with indicated heights
    // post BIP34 before approximately height 486,000,000. After block
    // 1,983,702 testnet3 starts doing unnecessary BIP30 checking again.
    assert(pindex->pprev);
    CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(m_params.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == m_params.GetConsensus().BIP34Hash));

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have a
    // consensus change that ensures coinbases at those heights cannot
    // duplicate earlier coinbases.
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    LogPrintf("ERROR: ConnectBlock(): tried to overwrite transaction\n");
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30");
                }
            }
        }
    }

    // Enforce BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY)
    int nLockTimeFlags = 0;
    if (pindex->pprev && IsBTC16BIPsEnabled(pindex->pprev->nTime)) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, m_params.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    // Precomputed transaction data pointers must not be invalidated
    // until after `control` has run the script checks (potentially
    // in multiple threads). Preallocate the vector size so a new allocation
    // doesn't invalidate pointers into the vector, and keep txsdata in scope
    // for as long as `control`.
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && g_parallel_script_checks ? &scriptcheckqueue : nullptr);
    std::vector<PrecomputedTransactionData> txsdata(block.vtx.size());

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            CAmount txfee = 0;
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee, Params().GetConsensus(), tx.nTime ? tx.nTime : block.nTime, (pindex->pprev? pindex->pprev->nMoneySupply : 0))) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                            tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
            }
            for (unsigned int i = 0; i < tx.vin.size(); i++)
                nValueIn += view.AccessCoin(tx.vin[i].prevout).out.nValue;
            nValueOut += tx.GetValueOut();
            if (!tx.IsCoinStake())
                nFees += txfee;
            if (!MoneyRange(nFees)) {
                LogPrintf("ERROR: %s: accumulated fee in the block out of range.\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)) {
                LogPrintf("ERROR: %s: contains a non-BIP68-final transaction\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal");
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
            LogPrintf("ERROR: ConnectBlock(): too many sigops\n");
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops");
        }

        if (!tx.IsCoinBase())
        {
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            TxValidationState tx_state;
            if (fScriptChecks && !CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txsdata[i], g_parallel_script_checks ? &vChecks : nullptr)) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("ConnectBlock(): CheckInputScripts on %s failed with %s",
                    tx.GetHash().ToString(), state.ToString());
            }
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight, IsProtocolV12(pindex));
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    // peercoin: coinbase reward check relocated to CheckBlock()

    if (!control.Wait()) {
        LogPrintf("ERROR: %s: CheckQueue failed\n", __func__);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-validation-failed");
    }
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

    if (fJustCheck)
        return true;

    // peercoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;

    // peercoin: fees are not collected by miners as in bitcoin
    // peercoin: fees are destroyed to compensate the entire network
    if (gArgs.GetBoolArg("-printcreation", false))
        LogPrintf("%s: destroy=%s nFees=%lld\n", __func__, FormatMoney(nFees), nFees);

    if (!m_blockman.WriteUndoDataForBlock(blockundo, state, pindex, m_params)) {
        return false;
    }

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        m_blockman.m_dirty_blockindex.insert(pindex);
    }

    assert(pindex->phashBlock);
    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    TRACE6(validation, block_connected,
        block_hash.data(),
        pindex->nHeight,
        block.vtx.size(),
        nInputs,
        nSigOpsCost,
        nTime5 - nTimeStart // in microseconds (µs)
    );

    return true;
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState()
{
    AssertLockHeld(::cs_main);
    return this->GetCoinsCacheSizeState(
        m_coinstip_cache_size_bytes,
        gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(
    size_t max_coins_cache_size_bytes,
    size_t max_mempool_size_bytes)
{
    AssertLockHeld(::cs_main);
    const int64_t nMempoolUsage = m_mempool ? m_mempool->DynamicMemoryUsage() : 0;
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage();
    int64_t nTotalSpace =
        max_coins_cache_size_bytes + std::max<int64_t>(int64_t(max_mempool_size_bytes) - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES = 10 * 1024 * 1024;  // 10MB
    int64_t large_threshold =
        std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogPrintf("Cache size (%s) exceeds total space (%s)\n", cacheSize, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool CChainState::FlushStateToDisk(
    BlockValidationState &state,
    FlushStateMode mode,
    int nManualPruneHeight)
{
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    static std::chrono::microseconds nLastWrite{0};
    static std::chrono::microseconds nLastFlush{0};
    bool full_flush_completed = false;

    const size_t coins_count = CoinsTip().GetCacheSize();
    const size_t coins_mem_usage = CoinsTip().DynamicMemoryUsage();

    try {
    {
        bool fDoFullFlush = false;

        CoinsCacheSizeState cache_state = GetCoinsCacheSizeState();
        LOCK(m_blockman.cs_LastBlockFile);
            // make sure we don't prune above the blockfilterindexes bestblocks
            // pruning is height-based
            int last_prune = m_chain.Height(); // last height we can prune
            ForEachBlockFilterIndex([&](BlockFilterIndex& index) {
               last_prune = std::max(1, std::min(last_prune, index.GetSummary().best_block_height));
            });

        const auto nNow = GetTime<std::chrono::microseconds>();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite.count() == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush.count() == 0) {
            nLastFlush = nNow;
        }
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FlushStateMode::PERIODIC && cache_state >= CoinsCacheSizeState::LARGE;
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cache_state >= CoinsCacheSizeState::CRITICAL;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + DATABASE_WRITE_INTERVAL;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + DATABASE_FLUSH_INTERVAL;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Ensure we can write block index
            if (!CheckDiskSpace(gArgs.GetBlocksDirPath())) {
                return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
            }
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block and undo data to disk", BCLog::BENCH);

                // First make sure all block and undo data is flushed to disk.
                m_blockman.FlushBlockFile();
            }

            // Then update all block file information (which may refer to block and undo files).
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block index to disk", BCLog::BENCH);

                if (!m_blockman.WriteBlockIndexDB()) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !CoinsTip().GetBestBlock().IsNull()) {
            LOG_TIME_MILLIS_WITH_CATEGORY(strprintf("write coins cache to disk (%d coins, %.2fkB)",
                coins_count, coins_mem_usage / 1000), BCLog::BENCH);

            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(gArgs.GetDataDirNet(), 48 * 2 * 2 * CoinsTip().GetCacheSize())) {
                return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!CoinsTip().Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
            full_flush_completed = true;
            TRACE4(utxocache, flush,
                   (int64_t)(GetTimeMicros() - nNow.count()), // in microseconds (µs)
                   (u_int32_t)mode,
                   (u_int64_t)coins_count,
                   (u_int64_t)coins_mem_usage);
        }
    }
    if (full_flush_completed) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().ChainStateFlushed(m_chain.GetLocator());
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void CChainState::ForceFlushStateToDisk()
{
    BlockValidationState state;
    if (!this->FlushStateToDisk(state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

/** Private helper function that concatenates warning messages. */
static void AppendWarning(bilingual_str& res, const bilingual_str& warn)
{
    if (!res.empty()) res += Untranslated(", ");
    res += warn;
}

static void UpdateTipLog(
    const CCoinsViewCache& coins_tip,
    const CBlockIndex* tip,
    const CChainParams& params,
    const std::string& func_name,
    const std::string& prefix,
    const std::string& warning_messages) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{

    AssertLockHeld(::cs_main);
    LogPrintf("%s%s: new best=%s height=%d version=0x%08x log2_work=%f tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)%s\n",
        prefix, func_name,
        tip->GetBlockHash().ToString(), tip->nHeight, tip->nVersion,
        log(tip->nChainTrust.getdouble()) / log(2.0), (unsigned long)tip->nChainTx,
        FormatISO8601DateTime(tip->GetBlockTime()),
        GuessVerificationProgress(params.TxData(), tip),
        coins_tip.DynamicMemoryUsage() * (1.0 / (1 << 20)),
        coins_tip.GetCacheSize(),
        !warning_messages.empty() ? strprintf(" warning='%s'", warning_messages) : "");
}

void CChainState::UpdateTip(const CBlockIndex* pindexNew)
{
    AssertLockHeld(::cs_main);
    const auto& coins_tip = this->CoinsTip();

    // The remainder of the function isn't relevant if we are not acting on
    // the active chainstate, so return if need be.
    if (this != &m_chainman.ActiveChainstate()) {
        // Only log every so often so that we don't bury log messages at the tip.
        constexpr int BACKGROUND_LOG_INTERVAL = 2000;
        if (pindexNew->nHeight % BACKGROUND_LOG_INTERVAL == 0) {
            UpdateTipLog(coins_tip, pindexNew, m_params, __func__, "[background validation] ", "");
        }
        return;
    }

    // New best block
    if (m_mempool) {
        m_mempool->AddTransactionsUpdated(1);
    }

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

    bilingual_str warning_messages;
    if (!this->IsInitialBlockDownload()) {
        const CBlockIndex* pindex = pindexNew;
    }

    UpdateTipLog(coins_tip, pindexNew, m_params, __func__, "", warning_messages.original);
}

/** Disconnect m_chain's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling MaybeUpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(BlockValidationState& state, DisconnectedBlockTransactions* disconnectpool)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    CBlockIndex *pindexDelete = m_chain.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, m_params.GetConsensus())) {
        return error("DisconnectTip(): Failed to read block");
    }
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(&CoinsTip());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }

    if (disconnectpool && m_mempool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            m_mempool->removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    m_chain.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock, pindexDelete);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    PerBlockConnectTrace() {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;

public:
    explicit ConnectTrace() : blocksConnected(1) {}

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        blocksConnected.pop_back();
        return blocksConnected;
    }
};

/**
 * Connect a new block to m_chain. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(BlockValidationState& state, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions& disconnectpool)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    assert(pindexNew->pprev == m_chain.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, m_params.GetConsensus())) {
            return AbortNode(state, "Failed to read block");
        }
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    {
        CCoinsViewCache view(&CoinsTip());
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), state.ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        assert(nBlocksTotal > 0);
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    if (m_mempool) {
        m_mempool->removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
        disconnectpool.removeForBlock(blockConnecting.vtx);
    }
    // Update m_chain & related variables.
    m_chain.SetTip(pindexNew);
    UpdateTip(pindexNew);

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain()
{
    AssertLockHeld(::cs_main);
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !m_chain.Contains(pindexTest)) {
            assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (m_chainman.m_best_invalid == nullptr || pindexNew->nChainTrust > m_chainman.m_best_invalid->nChainTrust)) {
                    m_chainman.m_best_invalid = pindexNew;
                }
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to m_blocks_unlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        m_blockman.m_blocks_unlinked.insert(
                            std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 *
 * @returns true unless a system error occurred
 */
bool CChainState::ActivateBestChainStep(BlockValidationState& state, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    const CBlockIndex* pindexOldTip = m_chain.Tip();
    const CBlockIndex* pindexFork = m_chain.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (m_chain.Tip() && m_chain.Tip() != pindexFork) {
        if (!DisconnectTip(state, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            MaybeUpdateMempoolForReorg(disconnectpool, false);

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            AbortNode(state, "Failed to disconnect block; see debug.log for details");
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect (in descending height order).
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex* pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex* pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = BlockValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    MaybeUpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || m_chain.Tip()->nChainTrust > pindexOldTip->nChainTrust) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        MaybeUpdateMempoolForReorg(disconnectpool, true);
    }
    if (m_mempool) m_mempool->check(this->CoinsTip(), this->m_chain.Height() + 1);

    CheckForkWarningConditions();

    return true;
}

static SynchronizationState GetSynchronizationState(bool init)
{
    if (!init) return SynchronizationState::POST_INIT;
    if (::fReindex) return SynchronizationState::INIT_REINDEX;
    return SynchronizationState::INIT_DOWNLOAD;
}

static bool NotifyHeaderTip(CChainState& chainstate) LOCKS_EXCLUDED(cs_main) {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = chainstate.IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(GetSynchronizationState(fInitialBlockDownload), pindexHeader);
    }
    return fNotify;
}

static void LimitValidationInterfaceQueue() LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    if (GetMainSignals().CallbacksPending() > 10) {
        SyncWithValidationInterfaceQueue();
    }
}

bool CChainState::ActivateBestChain(BlockValidationState& state, std::shared_ptr<const CBlock> pblock)
{
    AssertLockNotHeld(m_chainstate_mutex);

    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(::cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_chainstate_mutex to enforce mutual exclusion so that only one caller may execute this function at a time
    LOCK(m_chainstate_mutex);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetIntArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        LimitValidationInterfaceQueue();

        {
            LOCK(cs_main);
            // Lock transaction pool for at least as long as it takes for connectTrace to be consumed
            LOCK(MempoolMutex());
            CBlockIndex* starting_tip = m_chain.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace; // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == m_chain.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace)) {
                    // A system error occurred
                    return false;
                }
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = m_chain.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex);
                }
            } while (!m_chain.Tip() || (starting_tip && CBlockIndexWorkComparator()(m_chain.Tip(), starting_tip)));
            if (!blocks_connected) return true;

            const CBlockIndex* pindexFork = m_chain.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(GetSynchronizationState(fInitialDownload), pindexNewTip);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested()) break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex();

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FlushStateMode::PERIODIC)) {
        return false;
    }

    return true;
}

bool CChainState::PreciousBlock(BlockValidationState& state, CBlockIndex* pindex)
{
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);
    {
        LOCK(cs_main);
        if (pindex->nChainTrust < m_chain.Tip()->nChainTrust) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (m_chain.Tip()->nChainTrust > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = m_chain.Tip()->nChainTrust;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->HaveTxsDownloaded()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, std::shared_ptr<const CBlock>());
}

bool CChainState::InvalidateBlock(BlockValidationState& state, CBlockIndex* pindex)
{
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);

    // Genesis block can't be invalidated
    assert(pindex);
    if (pindex->nHeight == 0) return false;

    CBlockIndex* to_mark_failed = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // We do not allow ActivateBestChain() to run while InvalidateBlock() is
    // running, as that could cause the tip to change while we disconnect
    // blocks.
    LOCK(m_chainstate_mutex);

    // We'll be acquiring and releasing cs_main below, to allow the validation
    // callbacks to run. However, we should keep the block index in a
    // consistent state as we disconnect blocks -- in particular we need to
    // add equal-work blocks to setBlockIndexCandidates as we disconnect.
    // To avoid walking the block index repeatedly in search of candidates,
    // build a map once so that we can look up candidate blocks by chain
    // work as we go.
    std::multimap<const arith_uint256, CBlockIndex *> candidate_blocks_by_work;

    {
        LOCK(cs_main);
        for (const auto& entry : m_blockman.m_block_index) {
            CBlockIndex *candidate = entry.second;
            // We don't need to put anything in our active chain into the
            // multimap, because those candidates will be found and considered
            // as we disconnect.
            // Instead, consider only non-active-chain blocks that have at
            // least as much work as where we expect the new tip to end up.
            if (!m_chain.Contains(candidate) &&
                    !CBlockIndexWorkComparator()(candidate, pindex->pprev) &&
                    candidate->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                    candidate->HaveTxsDownloaded()) {
                candidate_blocks_by_work.insert(std::make_pair(candidate->nChainTrust, candidate));
            }
        }
    }

    // Disconnect (descendants of) pindex, and mark them invalid.
    while (true) {
        if (ShutdownRequested()) break;

        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        LOCK(cs_main);
        // Lock for as long as disconnectpool is in scope to make sure MaybeUpdateMempoolForReorg is
        // called after DisconnectTip without unlocking in between
        LOCK(MempoolMutex());
        if (!m_chain.Contains(pindex)) break;
        pindex_was_in_chain = true;
        CBlockIndex *invalid_walk_tip = m_chain.Tip();

        // ActivateBestChain considers blocks already in m_chain
        // unconditionally valid already, so force disconnect away from it.
        DisconnectedBlockTransactions disconnectpool;
        bool ret = DisconnectTip(state, &disconnectpool);
        // DisconnectTip will add transactions to disconnectpool.
        // Adjust the mempool to be consistent with the new tip, adding
        // transactions back to the mempool if disconnecting was successful,
        // and we're not doing a very deep invalidation (in which case
        // keeping the mempool up to date is probably futile anyway).
        MaybeUpdateMempoolForReorg(disconnectpool, /* fAddToMempool = */ (++disconnected <= 10) && ret);
        if (!ret) return false;
        assert(invalid_walk_tip->pprev == m_chain.Tip());

        // We immediately mark the disconnected blocks as invalid.
        // This prevents a case where pruned nodes may fail to invalidateblock
        // and be left unable to start as they have no tip candidates (as there
        // are no blocks that meet the "have data and are not invalid per
        // nStatus" criteria for inclusion in setBlockIndexCandidates).
        invalid_walk_tip->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_dirty_blockindex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        setBlockIndexCandidates.insert(invalid_walk_tip->pprev);
        if (invalid_walk_tip->pprev == to_mark_failed && (to_mark_failed->nStatus & BLOCK_FAILED_VALID)) {
            // We only want to mark the last disconnected block as BLOCK_FAILED_VALID; its children
            // need to be BLOCK_FAILED_CHILD instead.
            to_mark_failed->nStatus = (to_mark_failed->nStatus ^ BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
            m_blockman.m_dirty_blockindex.insert(to_mark_failed);
        }

        // Add any equal or more work headers to setBlockIndexCandidates
        auto candidate_it = candidate_blocks_by_work.lower_bound(invalid_walk_tip->pprev->nChainTrust);
        while (candidate_it != candidate_blocks_by_work.end()) {
            if (!CBlockIndexWorkComparator()(candidate_it->second, invalid_walk_tip->pprev)) {
                setBlockIndexCandidates.insert(candidate_it->second);
                candidate_it = candidate_blocks_by_work.erase(candidate_it);
            } else {
                ++candidate_it;
            }
        }

        // Track the last disconnected block, so we can correct its BLOCK_FAILED_CHILD status in future
        // iterations, or, if it's the last one, call InvalidChainFound on it.
        to_mark_failed = invalid_walk_tip;
    }

    CheckBlockIndex();

    {
        LOCK(cs_main);
        if (m_chain.Contains(to_mark_failed)) {
            // If the to-be-marked invalid block is in the active chain, something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid, even when it never was in the main chain
        to_mark_failed->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_dirty_blockindex.insert(to_mark_failed);
        setBlockIndexCandidates.erase(to_mark_failed);
        m_chainman.m_failed_blocks.insert(to_mark_failed);

        // If any new blocks somehow arrived while we were disconnecting
        // (above), then the pre-calculation of what should go into
        // setBlockIndexCandidates may have missed entries. This would
        // technically be an inconsistency in the block index, but if we clean
        // it up here, this should be an essentially unobservable error.
        // Loop back over all block index entries and add any missing entries
        // to setBlockIndexCandidates.
        BlockMap::iterator it = m_blockman.m_block_index.begin();
        while (it != m_blockman.m_block_index.end()) {
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && !setBlockIndexCandidates.value_comp()(it->second, m_chain.Tip())) {
                setBlockIndexCandidates.insert(it->second);
            }
            it++;
        }

        InvalidChainFound(to_mark_failed);
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        uiInterface.NotifyBlockTip(GetSynchronizationState(IsInitialBlockDownload()), to_mark_failed->pprev);
    }
    return true;
}

void CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = m_blockman.m_block_index.begin();
    while (it != m_blockman.m_block_index.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            m_blockman.m_dirty_blockindex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && setBlockIndexCandidates.value_comp()(m_chain.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == m_chainman.m_best_invalid) {
                // Reset invalid block marker if it was pointing to one of those.
                m_chainman.m_best_invalid = nullptr;
            }
            m_chainman.m_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            m_blockman.m_dirty_blockindex.insert(pindex);
            m_chainman.m_failed_blocks.erase(pindex);
        }
        pindex = pindex->pprev;
    }
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
void CChainState::ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const FlatFilePos& pos)
{
    AssertLockHeld(cs_main);
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (pindexNew->pprev && IsBTC16BIPsEnabled(pindexNew->pprev->nTime)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    m_blockman.m_dirty_blockindex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveTxsDownloaded()) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            pindex->nSequenceId = nBlockSequenceId++;
            if (m_chain.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = m_blockman.m_blocks_unlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                m_blockman.m_blocks_unlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            m_blockman.m_blocks_unlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
}

static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    return true;
}

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSignature)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW && !block.IsProofOfStake()))
        return false;

    // Signet only: check block solution
    if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
    }

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txnmrklroot", "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate", "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");

    // peercoin: only the second transaction can be the optional coinstake
    for (unsigned int i = 2; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinStake())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-missing", "coinstake in wrong position");

    // peercoin: first coinbase output should be empty if proof-of-stake block
    if (block.IsProofOfStake() && !block.vtx[0]->vout[0].IsEmpty())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-notempty", "coinbase output not empty in PoS block");

    // Check coinbase timestamp
    if (block.GetBlockTime() > (block.vtx[0]->nTime ? (int64_t)block.vtx[0]->nTime : block.GetBlockTime()) + (IsProtocolV09(block.GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-time", "coinbase timestamp is too early");

    // Check coinstake timestamp
    if (block.IsProofOfStake() && !CheckCoinStakeTimestamp(block.GetBlockTime(), block.vtx[1]->nTime ? (int64_t)block.vtx[1]->nTime : block.GetBlockTime()))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-time", "coinstake timestamp violation");

    // Check coinbase reward
    CAmount nCoinbaseCost = 0;
    if (block.IsProofOfWork())
        nCoinbaseCost = (GetMinFee(*block.vtx[0], block.nTime) < PERKB_TX_FEE)? 0 : (GetMinFee(*block.vtx[0], block.nTime) - PERKB_TX_FEE);
    if (block.vtx[0]->GetValueOut() > (block.IsProofOfWork()? (GetProofOfWorkReward(block.nBits, block.GetBlockTime()) - nCoinbaseCost) : 0))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount",
                strprintf("CheckBlock() : coinbase reward exceeded %s > %s",
                   FormatMoney(block.vtx[0]->GetValueOut()),
                   FormatMoney(block.IsProofOfWork()? GetProofOfWorkReward(block.nBits, block.GetBlockTime()) : 0)));
    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
            // peercoin: check transaction timestamp
            if (block.GetBlockTime() < (int64_t)tx->nTime)
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-time", strprintf("%s : block timestamp earlier than transaction timestamp", __func__));
        }
    }
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    // peercoin: check block signature
    // Only check block signature if check merkle root, c.f. commit 3cd01fdf
    // rfc6: validate signatures of proof of stake blocks only after 0.8 fork
    if (fCheckMerkleRoot && fCheckSignature && (block.IsProofOfStake() || !IsBTC16BIPsEnabled(block.GetBlockTime())) && !CheckBlockSignature(block))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sign", strprintf("%s : bad block signature", __func__));

    return true;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT && IsBTC16BIPsEnabled(pindexPrev->nTime) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (commitpos == NO_WITNESS_COMMITMENT) {
        uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
        CHash256().Write(witnessroot).Write(ret).Finalize(witnessroot);
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        out.scriptPubKey[0] = OP_RETURN;
        out.scriptPubKey[1] = 0x24;
        out.scriptPubKey[2] = 0xaa;
        out.scriptPubKey[3] = 0x21;
        out.scriptPubKey[4] = 0xa9;
        out.scriptPubKey[5] = 0xed;
        memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
        commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
        CMutableTransaction tx(*block.vtx[0]);
        tx.vout.push_back(out);
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, BlockManager& blockman, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work or proof-of-stake
    const Consensus::Params& consensusParams = params.GetConsensus();
    if (block.nBits != GetNextTargetRequired(pindexPrev, block.nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect proof of work/stake");

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // BlockIndex().
        CBlockIndex* pcheckpoint = blockman.GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
            LogPrintf("ERROR: %s: forked chain older than last checkpoint (height %d)\n", __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-prior-to-checkpoint");
        }
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast() || block.GetBlockTime() + (IsProtocolV09(block.GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9) < pindexPrev->GetBlockTime())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + (IsProtocolV09(block.GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9))
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if ((block.nVersion < 2 && IsProtocolV06(pindexPrev)) ||
        (block.nVersion < 4 && IsProtocolV12(pindexPrev)))
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Enforce BIP113 (Median Time Past).
    int nLockTimeFlags = 0;
    if (pindexPrev && IsBTC16BIPsEnabled(pindexPrev->nTime)) {
        assert(pindexPrev != nullptr);
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (pindexPrev && IsProtocolV06(pindexPrev) && block.nVersion >= 2)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (pindexPrev && IsBTC16BIPsEnabled(pindexPrev->nTime)) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != NO_WITNESS_COMMITMENT) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-nonce-size", strprintf("%s : invalid witness reserved value size", __func__));
            }
            CHash256().Write(hashWitness).Write(block.vtx[0]->vin[0].scriptWitness.stack[0]).Finalize(hashWitness);
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-witness", strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

bool ChainstateManager::AcceptBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf{m_blockman.m_block_index.find(hash)};
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != m_blockman.m_block_index.end()) {
            // Block header is already known.
            CBlockIndex* pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                LogPrint(BCLog::VALIDATION, "%s: block %s is marked invalid\n", __func__, hash.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate");
            }
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus(), !(block.nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE))) {
            LogPrint(BCLog::VALIDATION, "%s: Consensus::CheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi{m_blockman.m_block_index.find(block.hashPrevBlock)};
        if (mi == m_blockman.m_block_index.end()) {
            LogPrint(BCLog::VALIDATION, "%s: %s prev block not found\n", __func__, hash.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
        }
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            LogPrint(BCLog::VALIDATION, "%s: %s prev block invalid\n", __func__, hash.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
        }
        if (!ContextualCheckBlockHeader(block, state, m_blockman, chainparams, pindexPrev, GetAdjustedTime())) {
            LogPrint(BCLog::VALIDATION, "%s: Consensus::ContextualCheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous block
            // hasn't been validated up to BLOCK_VALID_SCRIPTS. This is a performance
            // optimization, in the common case of adding a new block to the tip,
            // we don't need to iterate over the failed blocks list.
            for (const CBlockIndex* failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        m_blockman.m_dirty_blockindex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    LogPrint(BCLog::VALIDATION, "%s: %s prev block invalid\n", __func__, hash.ToString());
                    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
                }
            }
        }
    }
    CBlockIndex* pindex{m_blockman.AddToBlockIndex(block)};

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ChainstateManager::ProcessNewBlockHeaders(int32_t& nPoSTemperature, const uint256& lastAcceptedHeader, const std::vector<CBlockHeader>& headers, BlockValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex)
{
    AssertLockNotHeld(cs_main);
    {
        LOCK(cs_main);

        int nCooling = POW_HEADER_COOLING;
        if (headers[0].hashPrevBlock != lastAcceptedHeader && !lastAcceptedHeader.IsNull()) {
            nPoSTemperature += (18 + headers.size()) / 10;
            nCooling = 0;
        }

        for (const CBlockHeader& header : headers) {
            bool fPoS = header.nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;

            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            bool accepted{AcceptBlockHeader(header, state, chainparams, &pindex)};
            ActiveChainstate().CheckBlockIndex();

            if (!accepted) {
                nPoSTemperature += POW_HEADER_COOLING;
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }

            if (fPoS) {
                nPoSTemperature++;
            } else { // PoW
                nPoSTemperature -= nCooling;
                nPoSTemperature = std::max((int)nPoSTemperature, 0);
            }
        }
    }
    if (NotifyHeaderTip(ActiveChainstate())) {
        if (ActiveChainstate().IsInitialBlockDownload() && ppindex && *ppindex) {
            const CBlockIndex& last_accepted{**ppindex};
            const int64_t blocks_left{(GetTime() - last_accepted.GetBlockTime()) / chainparams.GetConsensus().nPowTargetSpacing};
            const double progress{100.0 * last_accepted.nHeight / (last_accepted.nHeight + blocks_left)};
            LogPrintf("Synchronizing blockheaders, height: %d (~%.2f%%)\n", last_accepted.nHeight, progress);
        }
    }
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;
    bool fCheckPoS = true;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    bool accepted_header{m_chainman.AcceptBlockHeader(block, state, m_params, &pindex)};
    CheckBlockIndex();

    if (!accepted_header)
        return false;

    // peercoin: we should only accept blocks that can be connected to a prev block with validated PoS
    if (fCheckPoS && pindex->pprev && !pindex->pprev->IsValid(BLOCK_VALID_TRANSACTIONS)) {
        return error("%s: this block does not connect to any valid known block", __func__);
    }

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (m_chain.Tip() ? pindex->nChainTrust >= m_chain.Tip()->nChainTrust : true);

    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead{pindex->nHeight > m_chain.Height() + int(MIN_BLOCKS_TO_KEEP)};

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.
    // Note that this would break the getblockfrompeer RPC

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainTrust < nMinimumChainWork) return true;
    }

    if (!CheckBlock(block, state, m_params.GetConsensus()) ||
        !ContextualCheckBlock(block, state, pindex->pprev)) {
        if (state.IsInvalid() && state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            m_blockman.m_dirty_blockindex.insert(pindex);
        }
        return error("%s: %s", __func__, state.ToString());
    }

    // peercoin: check PoS
    if (fCheckPoS && !PeercoinContextualBlockChecks(block, state, pindex, false, m_chainman.ActiveChainstate())) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_dirty_blockindex.insert(pindex);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-pos", "proof of stake is incorrect");
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!m_chainman.ActiveChainstate().IsInitialBlockDownload() && m_chain.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        FlatFilePos blockPos{m_blockman.SaveBlockToDisk(block, pindex->nHeight, m_chain, m_params, dbp)};
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    FlushStateToDisk(state, FlushStateMode::NONE);
    CheckBlockIndex();

    return true;
}

bool ChainstateManager::ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock>& block, bool force_processing, bool* new_block, CBlockIndex** ppindex, bool* fPoSDuplicate)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (new_block) *new_block = false;
        if (fPoSDuplicate) *fPoSDuplicate = false;
        BlockValidationState state;

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Skipping AcceptBlock() for CheckBlock() failures means that we will never mark a block as invalid if
        // CheckBlock() fails.  This is protective against consensus failure if there are any unknown forms of block
        // malleability that cause CheckBlock() to fail; see e.g. CVE-2012-2459 and
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-February/016697.html.  Because CheckBlock() is
        // not very expensive, the anti-DoS benefits of caching failure (of a definitely-invalid block) are not substantial.
        bool ret = CheckBlock(*block, state, chainparams.GetConsensus());
        if (ret) {
            // Store to disk
            ret = ActiveChainstate().AcceptBlock(block, state, &pindex, force_processing, nullptr, new_block);
        }
        if (ppindex)
            *ppindex = ret ? pindex : nullptr;
        if (!ret) {
            GetMainSignals().BlockChecked(*block, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.ToString());
        }

        if (pindex->IsProofOfStake() && !ActiveChainstate().IsInitialBlockDownload()) {
            int32_t ndx = univHash(pindex->hashProofOfStake);
            if (fPoSDuplicate && vStakeSeen[ndx] == pindex->hashProofOfStake)
                *fPoSDuplicate = true;
            vStakeSeen[ndx] = pindex->hashProofOfStake;
        }
    }

    NotifyHeaderTip(ActiveChainstate());

    BlockValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActiveChainstate().ActivateBestChain(state, block)) {
        return error("%s: ActivateBestChain failed (%s)", __func__, state.ToString());
    }

    return true;
}

MempoolAcceptResult ChainstateManager::ProcessTransaction(const CTransactionRef& tx, bool test_accept)
{
    AssertLockHeld(cs_main);
    CChainState& active_chainstate = ActiveChainstate();
    if (!active_chainstate.GetMempool()) {
        TxValidationState state;
        state.Invalid(TxValidationResult::TX_NO_MEMPOOL, "no-mempool");
        return MempoolAcceptResult::Failure(state);
    }
    auto result = AcceptToMemoryPool(active_chainstate, tx, GetTime(), /*bypass_limits=*/ false, test_accept);
    active_chainstate.GetMempool()->check(active_chainstate.CoinsTip(), active_chainstate.m_chain.Height() + 1);
    return result;
}

bool TestBlockValidity(BlockValidationState& state,
                       const CChainParams& chainparams,
                       CChainState& chainstate,
                       const CBlock& block,
                       CBlockIndex* pindexPrev,
                       bool fCheckPOW,
                       bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainstate.m_chain.Tip());
    CCoinsViewCache viewNew(&chainstate.CoinsTip());
    uint256 block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainstate.m_blockman, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, state.ToString());
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    if (!ContextualCheckBlock(block, state, pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, state.ToString());
    if (!chainstate.ConnectBlock(block, state, &indexDummy, viewNew, true)) {
        return false;
    }
    assert(state.IsValid());

    return true;
}

void CChainState::LoadMempool(const ArgsManager& args)
{
    if (!m_mempool) return;
    if (args.GetBoolArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
        ::LoadMempool(*m_mempool, *this);
    }
    m_mempool->SetIsLoaded(!ShutdownRequested());
}

bool CChainState::LoadChainTip()
{
    AssertLockHeld(cs_main);
    const CCoinsViewCache& coins_cache = CoinsTip();
    assert(!coins_cache.GetBestBlock().IsNull()); // Never called when the coins view is empty
    const CBlockIndex* tip = m_chain.Tip();

    if (tip && tip->GetBlockHash() == coins_cache.GetBestBlock()) {
        return true;
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = m_blockman.LookupBlockIndex(coins_cache.GetBestBlock());
    if (!pindex) {
        return false;
    }
    m_chain.SetTip(pindex);
    PruneBlockIndexCandidates();

    tip = m_chain.Tip();
    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
              tip->GetBlockHash().ToString(),
              m_chain.Height(),
              FormatISO8601DateTime(tip->GetBlockTime()),
              GuessVerificationProgress(m_params.TxData(), tip));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks…").translated, 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(
    CChainState& chainstate,
    const Consensus::Params& consensus_params,
    CCoinsView& coinsview,
    int nCheckLevel, int nCheckDepth)
{
    AssertLockHeld(cs_main);

    if (chainstate.m_chain.Tip() == nullptr || chainstate.m_chain.Tip()->pprev == nullptr) {
        return true;
    }

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainstate.m_chain.Height()) {
        nCheckDepth = chainstate.m_chain.Height();
    }
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(&coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]..."); /* Continued */

    const bool is_snapshot_cs{!chainstate.m_from_snapshot_blockhash};

    for (pindex = chainstate.m_chain.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone / 10;
        }
        uiInterface.ShowProgress(_("Verifying blocks…").translated, percentageDone, false);
        if (pindex->nHeight <= chainstate.m_chain.Height() - nCheckDepth) {
            break;
        }
        if (is_snapshot_cs && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If running under an assumeutxo snapshot, only go
            // back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, consensus_params)) {
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, consensus_params)) {
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
        }
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        size_t curr_coins_usage = coins.DynamicMemoryUsage() + chainstate.CoinsTip().DynamicMemoryUsage();

        if (nCheckLevel >= 3 && curr_coins_usage <= chainstate.m_coinstip_cache_size_bytes) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            DisconnectResult res = chainstate.DisconnectBlock(block, pindex, coins);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested()) return true;
    }
    if (pindexFailure) {
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainstate.m_chain.Height() - pindexFailure->nHeight + 1, nGoodTransactions);
    }

    // store block count as we move pindex at check level >= 4
    int block_count = chainstate.m_chain.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        while (pindex != chainstate.m_chain.Tip()) {
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone / 10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone / 10;
            }
            uiInterface.ShowProgress(_("Verifying blocks…").translated, percentageDone, false);
            pindex = chainstate.m_chain.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, consensus_params))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!chainstate.ConnectBlock(block, state, pindex, coins)) {
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
            }
            if (ShutdownRequested()) return true;
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", block_count, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs)
{
    AssertLockHeld(cs_main);
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, m_params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true, IsProtocolV12(pindex));
    }
    return true;
}

bool CChainState::ReplayBlocks()
{
    LOCK(cs_main);

    CCoinsView& db = this->CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<uint256> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks…").translated, 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (m_blockman.m_block_index.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = m_blockman.m_block_index[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (m_blockman.m_block_index.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = m_blockman.m_block_index[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, m_params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        uiInterface.ShowProgress(_("Replaying blocks…").translated, (int) ((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)) , false);
        if (!RollforwardBlock(pindex, cache)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

bool CChainState::NeedsRedownload() const
{
    AssertLockHeld(cs_main);

    // At and above m_params.SegwitHeight, segwit consensus rules must be validated
    CBlockIndex* block{m_chain.Tip()};

    while (block != nullptr && block->pprev && IsBTC16BIPsEnabled(block->pprev->nTime)) {
        if (!(block->nStatus & BLOCK_OPT_WITNESS)) {
            // block is insufficiently validated for a segwit client
            return true;
        }
        block = block->pprev;
    }

    return false;
}

void CChainState::UnloadBlockIndex()
{
    AssertLockHeld(::cs_main);
    nBlockSequenceId = 1;
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex(CTxMemPool* mempool, ChainstateManager& chainman)
{
    LOCK(cs_main);
    chainman.Unload();
    pindexBestHeader = nullptr;
    if (mempool) mempool->clear();
}

bool ChainstateManager::LoadBlockIndex()
{
    AssertLockHeld(cs_main);
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = m_blockman.LoadBlockIndexDB(*this);
        if (!ret) return false;
        needs_init = m_blockman.m_block_index.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
    }
    return true;
}

bool CChainState::LoadGenesisBlock()
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // m_blockman.m_block_index. Note that we can't use m_chain here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (m_blockman.m_block_index.count(m_params.GenesisBlock().GetHash()))
        return true;

    try {
        const CBlock& block = m_params.GenesisBlock();
        FlatFilePos blockPos{m_blockman.SaveBlockToDisk(block, 0, m_chain, m_params, nullptr)};
        if (blockPos.IsNull()) {
            return error("%s: writing genesis block to disk failed", __func__);
        }
        CBlockIndex *pindex = m_blockman.AddToBlockIndex(block);
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

void CChainState::LoadExternalBlockFile(FILE* fileIn, FlatFilePos* dbp)
{
    AssertLockNotHeld(m_chainstate_mutex);
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, FlatFilePos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            if (ShutdownRequested()) return;

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(m_params.MessageStart()[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> buf;
                if (memcmp(buf, m_params.MessageStart(), CMessageHeader::MESSAGE_START_SIZE)) {
                    continue;
                }
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != m_params.GetConsensus().hashGenesisBlock && !m_blockman.LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                        continue;
                    }

                    // process in case the block isn't known yet
                    CBlockIndex* pindex = m_blockman.LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                      BlockValidationState state;
                      if (AcceptBlock(pblock, state, nullptr, true, dbp, nullptr)) {
                          nLoaded++;
                      }
                      if (state.IsError()) {
                          break;
                      }
                    } else if (hash != m_params.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                        LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == m_params.GetConsensus().hashGenesisBlock) {
                    BlockValidationState state;
                    if (!ActivateBestChain(state, nullptr)) {
                        break;
                    }
                }

                NotifyHeaderTip(*this);

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, FlatFilePos>::iterator, std::multimap<uint256, FlatFilePos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, FlatFilePos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, m_params.GetConsensus())) {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            BlockValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, nullptr, true, &it->second, nullptr)) {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip(*this);
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
}

void CChainState::CheckBlockIndex()
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in m_blockman.m_block_index but no active chain. (A few of the
    // tests when iterating the block tree require that m_chain has been initialized.)
    if (m_chain.Height() < 0) {
        assert(m_blockman.m_block_index.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (const std::pair<const uint256, CBlockIndex*>& entry : m_blockman.m_block_index) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == m_blockman.m_block_index.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        // Assumed-valid index entries will not have data since we haven't downloaded the
        // full block yet.
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA) && !pindex->IsAssumedValid()) {
            pindexFirstMissing = pindex;
        }
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;

        if (pindex->pprev != nullptr && !pindex->IsAssumedValid()) {
            // Skip validity flag checks for BLOCK_ASSUMED_VALID index entries, since these
            // *_VALID_MASK flags will not be present for index entries we are temporarily assuming
            // valid.
            if (pindexFirstNotTransactionsValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) {
                pindexFirstNotTransactionsValid = pindex;
            }

            if (pindexFirstNotChainValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) {
                pindexFirstNotChainValid = pindex;
            }

            if (pindexFirstNotScriptsValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
                pindexFirstNotScriptsValid = pindex;
            }
        }

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == m_params.GetConsensus().hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == m_chain.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (!pindex->HaveTxsDownloaded()) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
        assert(pindexFirstMissing == pindexFirstNeverProcessed);
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        if (pindex->IsAssumedValid()) {
            // Assumed-valid blocks should have some nTx value.
            assert(pindex->nTx > 0);
            // Assumed-valid blocks should connect to the main chain.
            assert((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE);
        } else {
            // Otherwise there should only be an nTx value if we have
            // actually seen a block's transactions.
            assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        }
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to HaveTxsDownloaded().
        assert((pindexFirstNeverProcessed == nullptr) == pindex->HaveTxsDownloaded());
        assert((pindexFirstNotTransactionsValid == nullptr) == pindex->HaveTxsDownloaded());
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainTrust >= pindex->pprev->nChainTrust); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All m_blockman.m_block_index entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                const bool is_active = this == &m_chainman.ActiveChainstate();

                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates. m_chain.Tip() must also be there.
                //
                // Don't perform this check for the background chainstate since
                // its setBlockIndexCandidates shouldn't have some entries (i.e. those past the
                // snapshot block) which do exist in the block index for the active chainstate.
                if (is_active && (pindexFirstMissing == nullptr || pindex == m_chain.Tip())) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in m_blocks_unlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in m_blocks_unlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in m_blocks_unlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in m_blocks_unlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in m_blocks_unlinked.
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CChainState::ToString()
{
    AssertLockHeld(::cs_main);
    CBlockIndex* tip = m_chain.Tip();
    return strprintf("Chainstate [%s] @ height %d (%s)",
                     m_from_snapshot_blockhash ? "snapshot" : "ibd",
                     tip ? tip->nHeight : -1, tip ? tip->GetBlockHash().ToString() : "null");
}

bool CChainState::ResizeCoinsCaches(size_t coinstip_size, size_t coinsdb_size)
{
    AssertLockHeld(::cs_main);
    if (coinstip_size == m_coinstip_cache_size_bytes &&
            coinsdb_size == m_coinsdb_cache_size_bytes) {
        // Cache sizes are unchanged, no need to continue.
        return true;
    }
    size_t old_coinstip_size = m_coinstip_cache_size_bytes;
    m_coinstip_cache_size_bytes = coinstip_size;
    m_coinsdb_cache_size_bytes = coinsdb_size;
    CoinsDB().ResizeCache(coinsdb_size);

    LogPrintf("[%s] resized coinsdb cache to %.1f MiB\n",
        this->ToString(), coinsdb_size * (1.0 / 1024 / 1024));
    LogPrintf("[%s] resized coinstip cache to %.1f MiB\n",
        this->ToString(), coinstip_size * (1.0 / 1024 / 1024));

    BlockValidationState state;
    bool ret;

    if (coinstip_size > old_coinstip_size) {
        // Likely no need to flush if cache sizes have grown.
        ret = FlushStateToDisk(state, FlushStateMode::IF_NEEDED);
    } else {
        // Otherwise, flush state to disk and deallocate the in-memory coins map.
        ret = FlushStateToDisk(state, FlushStateMode::ALWAYS);
        CoinsTip().ReallocateCache();
    }
    return ret;
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(CTxMemPool& pool, CChainState& active_chainstate, FopenFn mockable_fopen_function)
{
    int64_t nExpiryTimeout = gArgs.GetIntArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr{mockable_fopen_function(gArgs.GetDataDirNet() / "mempool.dat", "rb")};
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t unbroadcast = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num) {
            --num;
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                pool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            if (nTime > nNow - nExpiryTimeout) {
                LOCK(cs_main);
                const auto& accepted = AcceptToMemoryPool(active_chainstate, tx, nTime, /*bypass_limits=*/false, /*test_accept=*/false);
                if (accepted.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (pool.exists(GenTxid::Txid(tx->GetHash()))) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            pool.PrioritiseTransaction(i.first, i.second);
        }

        std::set<uint256> unbroadcast_txids;
        file >> unbroadcast_txids;
        unbroadcast = unbroadcast_txids.size();
        for (const auto& txid : unbroadcast_txids) {
            // Ensure transactions were accepted to mempool then add to
            // unbroadcast set.
            if (pool.get(txid) != nullptr) pool.AddUnbroadcastTx(txid);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there, %i waiting for initial broadcast\n", count, failed, expired, already_there, unbroadcast);
    return true;
}

bool DumpMempool(const CTxMemPool& pool, FopenFn mockable_fopen_function, bool skip_file_commit)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;
    std::set<uint256> unbroadcast_txids;

    static Mutex dump_mutex;
    LOCK(dump_mutex);

    {
        LOCK(pool.cs);
        for (const auto &i : pool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = pool.infoAll();
        unbroadcast_txids = pool.GetUnbroadcastTxs();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr{mockable_fopen_function(gArgs.GetDataDirNet() / "mempool.dat.new", "wb")};
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << int64_t{count_seconds(i.m_time)};
            file << int64_t{i.nFeeDelta};
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;

        LogPrintf("Writing %d unbroadcast transactions to disk.\n", unbroadcast_txids.size());
        file << unbroadcast_txids;

        if (!skip_file_commit && !FileCommit(file.Get()))
            throw std::runtime_error("FileCommit failed");
        file.fclose();
        if (!RenameOver(gArgs.GetDataDirNet() / "mempool.dat.new", gArgs.GetDataDirNet() / "mempool.dat")) {
            throw std::runtime_error("Rename failed");
        }
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return std::min<double>(pindex->nChainTx / fTxTotal, 1.0);
}





// peercoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool GetCoinAge(const CTransaction& tx, const CCoinsViewCache &view, uint64_t& nCoinAge, unsigned int nTimeTx, bool isTrueCoinAge)
{
    arith_uint256 bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (tx.IsCoinBase())
        return true;

    // Transaction index is required to get to block header
    if (!g_txindex)
        return false;  // Transaction index not available

    for (const auto& txin : tx.vin)
    {
        // First try finding the previous transaction in database
        const COutPoint &prevout = txin.prevout;
        Coin coin;

        if (isTrueCoinAge && !view.GetCoin(prevout, coin))
            continue;  // previous transaction not in main chain
        if (nTimeTx < coin.nTime)
            return false;  // Transaction timestamp violation

        CDiskTxPos postx;
        CBlockHeader header;
        CTransactionRef txPrev;
        auto it = g_txindex->cachedTxs.find(prevout.hash);
        if (it != g_txindex->cachedTxs.end()) {
            header = it->second.first;
            txPrev = it->second.second;
        } else {
            if (g_txindex->FindTxPosition(prevout.hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                try {
                    file >> header;
                    fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                    file >> txPrev;
                } catch (std::exception &e) {
                    return error("%s() : deserialize or I/O error in GetCoinAge()", __PRETTY_FUNCTION__);
                }
            } else
                return error("%s() : tx missing in tx index in GetCoinAge()", __PRETTY_FUNCTION__);
            g_txindex->cachedTxs[prevout.hash] = std::pair(header,txPrev);
        }

        if (txPrev->GetHash() != prevout.hash)
            return error("%s() : txid mismatch in GetCoinAge()", __PRETTY_FUNCTION__);

        if (header.GetBlockTime() + Params().GetConsensus().nStakeMinAge > nTimeTx)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev->vout[txin.prevout.n].nValue;
        int nEffectiveAge = nTimeTx-(txPrev->nTime ? txPrev->nTime : header.GetBlockTime());

        if (!isTrueCoinAge || IsProtocolV09(nTimeTx))
            nEffectiveAge = std::min(nEffectiveAge, 365 * 24 * 60 * 60);

        bnCentSecond += arith_uint256(nValueIn) * nEffectiveAge / CENT;

        if (gArgs.GetBoolArg("-printcoinage", false))
            LogPrintf("coin age nValueIn=%-12lld nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nEffectiveAge, bnCentSecond.ToString());
    }

    arith_uint256 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (gArgs.GetBoolArg("-printcoinage", false))
        LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString());
    nCoinAge = bnCoinDay.GetLow64();
    return true;
}

// peercoin: sign block
typedef std::vector<unsigned char> valtype;
bool SignBlock(CBlock& block, const CWallet& keystore)
{
    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.IsProofOfStake()? block.vtx[1]->vout[1] : block.vtx[0]->vout[0];

    if (Solver(txout.scriptPubKey, vSolutions) != TxoutType::PUBKEY)
        return false;

    // Sign
    const valtype& vchPubKey = vSolutions[0];
    CKey key;
    if (!keystore.GetLegacyScriptPubKeyMan()->GetKey(CKeyID(Hash160(vchPubKey)), key))
        return false;
    if (key.GetPubKey() != CPubKey(vchPubKey))
        return false;
    return key.Sign(block.GetHash(), block.vchBlockSig, 0);
}

// peercoin: check block signature
bool CheckBlockSignature(const CBlock& block)
{
    if (block.GetHash() == Params().GetConsensus().hashGenesisBlock)
        return block.vchBlockSig.empty();

    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.IsProofOfStake()? block.vtx[1]->vout[1] : block.vtx[0]->vout[0];

    if (Solver(txout.scriptPubKey, vSolutions) != TxoutType::PUBKEY)
        return false;

    const valtype& vchPubKey = vSolutions[0];
    CPubKey key(vchPubKey);
    if (block.vchBlockSig.empty())
        return false;
    return key.Verify(block.GetHash(), block.vchBlockSig);
}

std::optional<uint256> ChainstateManager::SnapshotBlockhash() const
{
    LOCK(::cs_main);
    if (m_active_chainstate && m_active_chainstate->m_from_snapshot_blockhash) {
        // If a snapshot chainstate exists, it will always be our active.
        return m_active_chainstate->m_from_snapshot_blockhash;
    }
    return std::nullopt;
}

std::vector<CChainState*> ChainstateManager::GetAll()
{
    LOCK(::cs_main);
    std::vector<CChainState*> out;

    if (!IsSnapshotValidated() && m_ibd_chainstate) {
        out.push_back(m_ibd_chainstate.get());
    }

    if (m_snapshot_chainstate) {
        out.push_back(m_snapshot_chainstate.get());
    }

    return out;
}

CChainState& ChainstateManager::InitializeChainstate(
    CTxMemPool* mempool, const std::optional<uint256>& snapshot_blockhash)
{
    AssertLockHeld(::cs_main);
    bool is_snapshot = snapshot_blockhash.has_value();
    std::unique_ptr<CChainState>& to_modify =
        is_snapshot ? m_snapshot_chainstate : m_ibd_chainstate;

    if (to_modify) {
        throw std::logic_error("should not be overwriting a chainstate");
    }
    to_modify.reset(new CChainState(mempool, m_blockman, *this, snapshot_blockhash));

    // Snapshot chainstates and initial IBD chaintates always become active.
    if (is_snapshot || (!is_snapshot && !m_active_chainstate)) {
        LogPrintf("Switching active chainstate to %s\n", to_modify->ToString());
        m_active_chainstate = to_modify.get();
    } else {
        throw std::logic_error("unexpected chainstate activation");
    }

    return *to_modify;
}

const AssumeutxoData* ExpectedAssumeutxo(
    const int height, const CChainParams& chainparams)
{
    const MapAssumeutxo& valid_assumeutxos_map = chainparams.Assumeutxo();
    const auto assumeutxo_found = valid_assumeutxos_map.find(height);

    if (assumeutxo_found != valid_assumeutxos_map.end()) {
        return &assumeutxo_found->second;
    }
    return nullptr;
}

bool ChainstateManager::ActivateSnapshot(
        CAutoFile& coins_file,
        const SnapshotMetadata& metadata,
        bool in_memory)
{
    uint256 base_blockhash = metadata.m_base_blockhash;

    if (this->SnapshotBlockhash()) {
        LogPrintf("[snapshot] can't activate a snapshot-based chainstate more than once\n");
        return false;
    }

    int64_t current_coinsdb_cache_size{0};
    int64_t current_coinstip_cache_size{0};

    // Cache percentages to allocate to each chainstate.
    //
    // These particular percentages don't matter so much since they will only be
    // relevant during snapshot activation; caches are rebalanced at the conclusion of
    // this function. We want to give (essentially) all available cache capacity to the
    // snapshot to aid the bulk load later in this function.
    static constexpr double IBD_CACHE_PERC = 0.01;
    static constexpr double SNAPSHOT_CACHE_PERC = 0.99;

    {
        LOCK(::cs_main);
        // Resize the coins caches to ensure we're not exceeding memory limits.
        //
        // Allocate the majority of the cache to the incoming snapshot chainstate, since
        // (optimistically) getting to its tip will be the top priority. We'll need to call
        // `MaybeRebalanceCaches()` once we're done with this function to ensure
        // the right allocation (including the possibility that no snapshot was activated
        // and that we should restore the active chainstate caches to their original size).
        //
        current_coinsdb_cache_size = this->ActiveChainstate().m_coinsdb_cache_size_bytes;
        current_coinstip_cache_size = this->ActiveChainstate().m_coinstip_cache_size_bytes;

        // Temporarily resize the active coins cache to make room for the newly-created
        // snapshot chain.
        this->ActiveChainstate().ResizeCoinsCaches(
            static_cast<size_t>(current_coinstip_cache_size * IBD_CACHE_PERC),
            static_cast<size_t>(current_coinsdb_cache_size * IBD_CACHE_PERC));
    }

    auto snapshot_chainstate = WITH_LOCK(::cs_main,
        return std::make_unique<CChainState>(
            /* mempool */ nullptr, m_blockman, *this, base_blockhash));

    {
        LOCK(::cs_main);
        snapshot_chainstate->InitCoinsDB(
            static_cast<size_t>(current_coinsdb_cache_size * SNAPSHOT_CACHE_PERC),
            in_memory, false, "chainstate");
        snapshot_chainstate->InitCoinsCache(
            static_cast<size_t>(current_coinstip_cache_size * SNAPSHOT_CACHE_PERC));
    }

    const bool snapshot_ok = this->PopulateAndValidateSnapshot(
        *snapshot_chainstate, coins_file, metadata);

    if (!snapshot_ok) {
        WITH_LOCK(::cs_main, this->MaybeRebalanceCaches());
        return false;
    }

    {
        LOCK(::cs_main);
        assert(!m_snapshot_chainstate);
        m_snapshot_chainstate.swap(snapshot_chainstate);
        const bool chaintip_loaded = m_snapshot_chainstate->LoadChainTip();
        assert(chaintip_loaded);

        m_active_chainstate = m_snapshot_chainstate.get();

        LogPrintf("[snapshot] successfully activated snapshot %s\n", base_blockhash.ToString());
        LogPrintf("[snapshot] (%.2f MB)\n",
            m_snapshot_chainstate->CoinsTip().DynamicMemoryUsage() / (1000 * 1000));

        this->MaybeRebalanceCaches();
    }
    return true;
}

static void FlushSnapshotToDisk(CCoinsViewCache& coins_cache, bool snapshot_loaded)
{
    LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE(
        strprintf("%s (%.2f MB)",
                  snapshot_loaded ? "saving snapshot chainstate" : "flushing coins cache",
                  coins_cache.DynamicMemoryUsage() / (1000 * 1000)),
        BCLog::LogFlags::ALL);

    coins_cache.Flush();
}

bool ChainstateManager::PopulateAndValidateSnapshot(
    CChainState& snapshot_chainstate,
    CAutoFile& coins_file,
    const SnapshotMetadata& metadata)
{
    // It's okay to release cs_main before we're done using `coins_cache` because we know
    // that nothing else will be referencing the newly created snapshot_chainstate yet.
    CCoinsViewCache& coins_cache = *WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsTip());

    uint256 base_blockhash = metadata.m_base_blockhash;

    CBlockIndex* snapshot_start_block = WITH_LOCK(::cs_main, return m_blockman.LookupBlockIndex(base_blockhash));

    if (!snapshot_start_block) {
        // Needed for GetUTXOStats and ExpectedAssumeutxo to determine the height and to avoid a crash when base_blockhash.IsNull()
        LogPrintf("[snapshot] Did not find snapshot start blockheader %s\n",
                  base_blockhash.ToString());
        return false;
    }

    int base_height = snapshot_start_block->nHeight;
    auto maybe_au_data = ExpectedAssumeutxo(base_height, ::Params());

    if (!maybe_au_data) {
        LogPrintf("[snapshot] assumeutxo height in snapshot metadata not recognized " /* Continued */
                  "(%d) - refusing to load snapshot\n", base_height);
        return false;
    }

    const AssumeutxoData& au_data = *maybe_au_data;

    COutPoint outpoint;
    Coin coin;
    const uint64_t coins_count = metadata.m_coins_count;
    uint64_t coins_left = metadata.m_coins_count;

    LogPrintf("[snapshot] loading coins from snapshot %s\n", base_blockhash.ToString());
    int64_t coins_processed{0};

    while (coins_left > 0) {
        try {
            coins_file >> outpoint;
            coins_file >> coin;
        } catch (const std::ios_base::failure&) {
            LogPrintf("[snapshot] bad snapshot format or truncated snapshot after deserializing %d coins\n",
                      coins_count - coins_left);
            return false;
        }
        if (coin.nHeight > base_height ||
            outpoint.n >= std::numeric_limits<decltype(outpoint.n)>::max() // Avoid integer wrap-around in coinstats.cpp:ApplyHash
        ) {
            LogPrintf("[snapshot] bad snapshot data after deserializing %d coins\n",
                      coins_count - coins_left);
            return false;
        }

        coins_cache.EmplaceCoinInternalDANGER(std::move(outpoint), std::move(coin));

        --coins_left;
        ++coins_processed;

        if (coins_processed % 1000000 == 0) {
            LogPrintf("[snapshot] %d coins loaded (%.2f%%, %.2f MB)\n",
                coins_processed,
                static_cast<float>(coins_processed) * 100 / static_cast<float>(coins_count),
                coins_cache.DynamicMemoryUsage() / (1000 * 1000));
        }

        // Batch write and flush (if we need to) every so often.
        //
        // If our average Coin size is roughly 41 bytes, checking every 120,000 coins
        // means <5MB of memory imprecision.
        if (coins_processed % 120000 == 0) {
            if (ShutdownRequested()) {
                return false;
            }

            const auto snapshot_cache_state = WITH_LOCK(::cs_main,
                return snapshot_chainstate.GetCoinsCacheSizeState());

            if (snapshot_cache_state >= CoinsCacheSizeState::CRITICAL) {
                // This is a hack - we don't know what the actual best block is, but that
                // doesn't matter for the purposes of flushing the cache here. We'll set this
                // to its correct value (`base_blockhash`) below after the coins are loaded.
                coins_cache.SetBestBlock(GetRandHash());

                // No need to acquire cs_main since this chainstate isn't being used yet.
                FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/false);
            }
        }
    }

    // Important that we set this. This and the coins_cache accesses above are
    // sort of a layer violation, but either we reach into the innards of
    // CCoinsViewCache here or we have to invert some of the CChainState to
    // embed them in a snapshot-activation-specific CCoinsViewCache bulk load
    // method.
    coins_cache.SetBestBlock(base_blockhash);

    bool out_of_coins{false};
    try {
        coins_file >> outpoint;
    } catch (const std::ios_base::failure&) {
        // We expect an exception since we should be out of coins.
        out_of_coins = true;
    }
    if (!out_of_coins) {
        LogPrintf("[snapshot] bad snapshot - coins left over after deserializing %d coins\n",
            coins_count);
        return false;
    }

    LogPrintf("[snapshot] loaded %d (%.2f MB) coins from snapshot %s\n",
        coins_count,
        coins_cache.DynamicMemoryUsage() / (1000 * 1000),
        base_blockhash.ToString());

    // No need to acquire cs_main since this chainstate isn't being used yet.
    FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/true);

    assert(coins_cache.GetBestBlock() == base_blockhash);

    CCoinsStats stats{CoinStatsHashType::HASH_SERIALIZED};
    auto breakpoint_fnc = [] { /* TODO insert breakpoint here? */ };

    // As above, okay to immediately release cs_main here since no other context knows
    // about the snapshot_chainstate.
    CCoinsViewDB* snapshot_coinsdb = WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsDB());

    if (!GetUTXOStats(snapshot_coinsdb, m_blockman, stats, breakpoint_fnc)) {
        LogPrintf("[snapshot] failed to generate coins stats\n");
        return false;
    }

    // Assert that the deserialized chainstate contents match the expected assumeutxo value.
    if (AssumeutxoHash{stats.hashSerialized} != au_data.hash_serialized) {
        LogPrintf("[snapshot] bad snapshot content hash: expected %s, got %s\n",
            au_data.hash_serialized.ToString(), stats.hashSerialized.ToString());
        return false;
    }

    snapshot_chainstate.m_chain.SetTip(snapshot_start_block);

    // The remainder of this function requires modifying data protected by cs_main.
    LOCK(::cs_main);

    // Fake various pieces of CBlockIndex state:
    CBlockIndex* index = nullptr;

    // Don't make any modifications to the genesis block.
    // This is especially important because we don't want to erroneously
    // apply BLOCK_ASSUMED_VALID to genesis, which would happen if we didn't skip
    // it here (since it apparently isn't BLOCK_VALID_SCRIPTS).
    constexpr int AFTER_GENESIS_START{1};

    for (int i = AFTER_GENESIS_START; i <= snapshot_chainstate.m_chain.Height(); ++i) {
        index = snapshot_chainstate.m_chain[i];

        // Fake nTx so that LoadBlockIndex() loads assumed-valid CBlockIndex
        // entries (among other things)
        if (!index->nTx) {
            index->nTx = 1;
        }
        // Fake nChainTx so that GuessVerificationProgress reports accurately
        index->nChainTx = index->pprev->nChainTx + index->nTx;

        // Mark unvalidated block index entries beneath the snapshot base block as assumed-valid.
        if (!index->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This flag will be removed once the block is fully validated by a
            // background chainstate.
            index->nStatus |= BLOCK_ASSUMED_VALID;
        }

        // Fake BLOCK_OPT_WITNESS so that CChainState::NeedsRedownload()
        // won't ask to rewind the entire assumed-valid chain on startup.
        if (IsBTC16BIPsEnabled(index->nTime)) {
            index->nStatus |= BLOCK_OPT_WITNESS;
        }

        m_blockman.m_dirty_blockindex.insert(index);
        // Changes to the block index will be flushed to disk after this call
        // returns in `ActivateSnapshot()`, when `MaybeRebalanceCaches()` is
        // called, since we've added a snapshot chainstate and therefore will
        // have to downsize the IBD chainstate, which will result in a call to
        // `FlushStateToDisk(ALWAYS)`.
    }

    assert(index);
    index->nChainTx = au_data.nChainTx;
    snapshot_chainstate.setBlockIndexCandidates.insert(snapshot_start_block);

    LogPrintf("[snapshot] validated snapshot (%.2f MB)\n",
        coins_cache.DynamicMemoryUsage() / (1000 * 1000));
    return true;
}

CChainState& ChainstateManager::ActiveChainstate() const
{
    LOCK(::cs_main);
    assert(m_active_chainstate);
    return *m_active_chainstate;
}

bool ChainstateManager::IsSnapshotActive() const
{
    LOCK(::cs_main);
    return m_snapshot_chainstate && m_active_chainstate == m_snapshot_chainstate.get();
}

void ChainstateManager::Unload()
{
    AssertLockHeld(::cs_main);
    for (CChainState* chainstate : this->GetAll()) {
        chainstate->m_chain.SetTip(nullptr);
        chainstate->UnloadBlockIndex();
    }

    m_failed_blocks.clear();
    m_blockman.Unload();
    m_best_invalid = nullptr;
}

void ChainstateManager::Reset()
{
    LOCK(::cs_main);
    m_ibd_chainstate.reset();
    m_snapshot_chainstate.reset();
    m_active_chainstate = nullptr;
    m_snapshot_validated = false;
}

void ChainstateManager::MaybeRebalanceCaches()
{
    AssertLockHeld(::cs_main);
    if (m_ibd_chainstate && !m_snapshot_chainstate) {
        LogPrintf("[snapshot] allocating all cache to the IBD chainstate\n");
        // Allocate everything to the IBD chainstate.
        m_ibd_chainstate->ResizeCoinsCaches(m_total_coinstip_cache, m_total_coinsdb_cache);
    }
    else if (m_snapshot_chainstate && !m_ibd_chainstate) {
        LogPrintf("[snapshot] allocating all cache to the snapshot chainstate\n");
        // Allocate everything to the snapshot chainstate.
        m_snapshot_chainstate->ResizeCoinsCaches(m_total_coinstip_cache, m_total_coinsdb_cache);
    }
    else if (m_ibd_chainstate && m_snapshot_chainstate) {
        // If both chainstates exist, determine who needs more cache based on IBD status.
        //
        // Note: shrink caches first so that we don't inadvertently overwhelm available memory.
        if (m_snapshot_chainstate->IsInitialBlockDownload()) {
            m_ibd_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.05, m_total_coinsdb_cache * 0.05);
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.95, m_total_coinsdb_cache * 0.95);
        } else {
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.05, m_total_coinsdb_cache * 0.05);
            m_ibd_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.95, m_total_coinsdb_cache * 0.95);
        }
    }
}
