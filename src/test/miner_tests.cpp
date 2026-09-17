// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <test/util/random.h>
#include <test/util/transaction_utils.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>
#include <pow.h>

#include <test/util/common.h>
#include <test/util/setup_common.h>

#include <memory>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;

namespace miner_tests {
struct MinerTestingSetup : public RegTestingSetup {
    void TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool TestSequenceLocks(const CTransaction& tx, CTxMemPool& tx_mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CCoinsViewMemPool view_mempool{&m_node.chainman->ActiveChainstate().CoinsTip(), tx_mempool};
        CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
        const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(tip, view_mempool, tx)};
        return lock_points.has_value() && CheckSequenceLocksAtTip(tip, *lock_points);
    }
    CTxMemPool& MakeMempool()
    {
        // Delete the previous mempool to ensure with valgrind that the old
        // pointer is not accessed, when the new one should be accessed
        // instead.
        m_node.mempool.reset();
        bilingual_str error;
        auto opts = MemPoolOptionsForTest(m_node);
        // The "block size > limit" test creates a cluster of 1192590 vbytes,
        // so set the cluster vbytes limit big enough so that the txgraph
        // doesn't become oversized.
        opts.limits.cluster_size_vbytes = 1'200'000;
        m_node.mempool = std::make_unique<CTxMemPool>(opts, error);
        Assert(error.empty());
        return *m_node.mempool;
    }
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node, /*wait_loaded=*/false);
    }

    // peercoin bridge: many upstream miner tests use synthetic Bitcoin values.
    // Fund the last output from the actual chain/mempool input value and ensure
    // PPC's consensus minimum fee is satisfied without hardcoding coinbase value.
    CAmount FundTransaction(CMutableTransaction& tx, CTxMemPool& tx_mempool, CAmount desired_fee = 0) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        BOOST_REQUIRE(!tx.vout.empty());

        CAmount input_total = 0;
        for (const auto& input : tx.vin) {
            if (auto prev_tx = tx_mempool.get(input.prevout.hash)) {
                if (input.prevout.n >= prev_tx->vout.size()) BOOST_FAIL("missing mempool output");
                input_total += prev_tx->vout[input.prevout.n].nValue;
            } else {
                auto coin = Assert(m_node.chainman)->ActiveChainstate().CoinsTip().GetCoin(input.prevout);
                if (!coin) BOOST_FAIL("missing chain output");
                if (input.prevout.n != 0) BOOST_FAIL("unexpected chain output index");
                input_total += coin->out.nValue;
            }
        }

        CAmount fixed_outputs = 0;
        for (size_t i = 0; i + 1 < tx.vout.size(); ++i) {
            fixed_outputs += tx.vout[i].nValue;
        }

        CAmount fee = desired_fee;
        for (int attempt = 0; attempt < 25; ++attempt) {
            if (input_total <= fixed_outputs + fee) BOOST_FAIL("not enough funds");
            tx.vout.back().nValue = input_total - fixed_outputs - fee;
            const CAmount min_fee = GetMinFee(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), tx.nTime ? static_cast<uint32_t>(tx.nTime) : 0);
            if (fee >= min_fee) return fee;
            fee = min_fee + 1;
            if (fee > MAX_MONEY) BOOST_FAIL("fee exceeds money range");
        }
        BOOST_FAIL("could not satisfy minimum fee");
        return 0;
    }
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);

constexpr static struct {
    unsigned int extranonce;
    unsigned int nonce;
} BLOCKINFO[]{{0, 3552706918},   {500, 37506755},   {1000, 948987788}, {400, 524762339},  {800, 258510074},  {300, 102309278},
              {1300, 54365202},  {600, 1107740426}, {1000, 203094491}, {900, 391178848},  {800, 381177271},  {600, 87188412},
              {0, 66522866},     {800, 874942736},  {1000, 89200838},  {400, 312638088},  {400, 66263693},   {500, 924648304},
              {400, 369913599},  {500, 47630099},   {500, 115045364},  {100, 277026602},  {1100, 809621409}, {700, 155345322},
              {800, 943579953},  {400, 28200730},   {900, 77200495},   {0, 105935488},    {400, 698721821},  {500, 111098863},
              {1300, 445389594}, {500, 621849894},  {1400, 56010046},  {1100, 370669776}, {1200, 380301940}, {1200, 110654905},
              {400, 213771024},  {1500, 120014726}, {1200, 835019014}, {1500, 624817237}, {900, 1404297},    {400, 189414558},
              {400, 293178348},  {1100, 15393789},  {600, 396764180},  {800, 1387046371}, {800, 199368303},  {700, 111496662},
              {100, 129759616},  {200, 536577982},  {500, 125881300},  {500, 101053391},  {1200, 471590548}, {900, 86957729},
              {1200, 179604104}, {600, 68658642},   {1000, 203295701}, {500, 139615361},  {900, 233693412},  {300, 153225163},
              {0, 27616254},     {1200, 9856191},   {100, 220392722},  {200, 66257599},   {1100, 145489641}, {1300, 37859442},
              {400, 5816075},    {1200, 215752117}, {1400, 32361482},  {1400, 6529223},   {500, 143332977},  {800, 878392},
              {700, 159290408},  {400, 123197595},  {700, 43988693},   {300, 304224916},  {700, 214771621},  {1100, 274148273},
              {400, 285632418},  {1100, 923451065}, {600, 12818092},   {1200, 736282054}, {1000, 246683167}, {600, 92950402},
              {1400, 29223405},  {1000, 841327192}, {700, 174301283},  {1400, 214009854}, {1000, 6989517},   {1200, 278226956},
              {700, 540219613},  {400, 93663104},   {1100, 152345635}, {1500, 464194499}, {1300, 333850111}, {600, 258311263},
              {600, 90173162},   {1000, 33590797},  {1500, 332866027}, {100, 204704427},  {1000, 463153545}, {800, 303244785},
              {600, 88096214},   {0, 137477892},    {1200, 195514506}, {300, 704114595},  {900, 292087369},  {1400, 758684870},
              {1300, 163493028}, {1200, 53151293}};

static std::unique_ptr<CBlockIndex> CreateBlockIndex(int nHeight, CBlockIndex* active_chain_tip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto index{std::make_unique<CBlockIndex>()};
    index->nHeight = nHeight;
    index->pprev = active_chain_tip;
    return index;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    LOCK(tx_mempool.cs);
    BOOST_CHECK(tx_mempool.size() == 0);

    // Block template should only have a coinbase when there's nothing in the mempool
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);

    // waitNext() on an empty mempool should return nullptr because there is no better template
    auto should_be_nullptr = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    BOOST_REQUIRE(should_be_nullptr == nullptr);

    // Unless fee_threshold is 0
    block_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 0});
    BOOST_REQUIRE(block_template);

    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;
    const CAmount LOWFEE = CENT;
    const CAmount MEDFEE = COIN;
    const CAmount HIGHFEE = 4 * COIN;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = scriptPubKey;
    CAmount low_fee = FundTransaction(tx, tx_mempool, LOWFEE);
    Txid hashParentTx = tx.GetHash();
    const auto parent_tx{entry.Fee(low_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    TryAddToMempool(tx_mempool, parent_tx);

    // This tx has a medium fee.
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].scriptPubKey = scriptPubKey;
    CAmount med_fee = FundTransaction(tx, tx_mempool, MEDFEE);
    Txid hashMediumFeeTx = tx.GetHash();
    const auto medium_fee_tx{entry.Fee(med_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    TryAddToMempool(tx_mempool, medium_fee_tx);

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].scriptPubKey = scriptPubKey;
    CAmount high_fee = FundTransaction(tx, tx_mempool, HIGHFEE);
    Txid hashHighFeeTx = tx.GetHash();
    const auto high_fee_tx{entry.Fee(high_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx)};
    TryAddToMempool(tx_mempool, high_fee_tx);

    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 4U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashHighFeeTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashMediumFeeTx);

    // Test the inclusion of package feerates in the block template and ensure they are sequential.
    const auto block_package_feerates = BlockAssembler{m_node.chainman->ActiveChainstate(), &tx_mempool, options}.CreateNewBlock(scriptPubKey)->m_package_feerates; // peercoin
    BOOST_CHECK(block_package_feerates.size() == 2);

    // parent_tx and high_fee_tx are added to the block as a package.
    const auto combined_txs_fee = parent_tx.GetFee() + high_fee_tx.GetFee();
    const auto combined_txs_size = parent_tx.GetTxSize() + high_fee_tx.GetTxSize();
    FeeFrac package_feefrac{combined_txs_fee, combined_txs_size};
    // The package should be added first.
    BOOST_CHECK(block_package_feerates[0] == package_feefrac);

    // The medium_fee_tx should be added next.
    FeeFrac medium_tx_feefrac{medium_fee_tx.GetFee(), medium_fee_tx.GetTxSize()};
    BOOST_CHECK(block_package_feerates[1] == medium_tx_feefrac);

    // peercoin bridge: test package selection with PPC's consensus minimum fee.
    // Every transaction is funded from its real inputs, and the template fee
    // threshold is set dynamically around the package feerate.
    struct BuiltTx {
        Txid hash;
        CAmount fee;
        uint64_t size;
    };
    auto add_spend = [&](const COutPoint& prev, CAmount desired_fee, bool spends_coinbase) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) -> BuiltTx {
        CMutableTransaction built;
        built.version = tx.version;
        built.nTime = tx.nTime;
        built.vin.resize(1);
        built.vin[0].prevout = prev;
        built.vin[0].scriptSig = CScript() << OP_1;
        built.vout.resize(1);
        built.vout[0].scriptPubKey = scriptPubKey;
        CAmount fee = FundTransaction(built, tx_mempool, desired_fee);
        Txid hash = built.GetHash();
        uint64_t size = ::GetSerializeSize(TX_WITH_WITNESS(built));
        TryAddToMempool(tx_mempool, entry.Fee(fee).Time(Now<NodeSeconds>()).SpendsCoinbase(spends_coinbase).FromTx(built));
        return {hash, fee, size};
    };
    auto block_includes = [](const CBlock& candidate, const Txid& hash) {
        for (const auto& tx_ref : candidate.vtx) {
            if (tx_ref->GetHash() == hash) return true;
        }
        return false;
    };

    auto add_multi_output_spend = [&](const COutPoint& prev, size_t output_count) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) -> BuiltTx {
        CMutableTransaction built;
        built.version = tx.version;
        built.nTime = tx.nTime;
        built.vin.resize(1);
        built.vin[0].prevout = prev;
        built.vin[0].scriptSig = CScript() << OP_1;
        built.vout.resize(output_count);

        CAmount input_value = 0;
        if (auto prev_tx = tx_mempool.get(prev.hash)) {
            input_value = prev_tx->vout.at(prev.n).nValue;
        } else {
            auto coin = Assert(m_node.chainman)->ActiveChainstate().CoinsTip().GetCoin(prev);
            if (!coin) BOOST_FAIL("missing split input");
            input_value = coin->out.nValue;
        }

        const CAmount fixed_each = input_value / (output_count + 1);
        for (size_t i = 0; i + 1 < output_count; ++i) {
            built.vout[i].nValue = fixed_each;
            built.vout[i].scriptPubKey = scriptPubKey;
        }
        built.vout.back().scriptPubKey = scriptPubKey;
        CAmount fee = FundTransaction(built, tx_mempool, 0);
        Txid hash = built.GetHash();
        uint64_t size = ::GetSerializeSize(TX_WITH_WITNESS(built));
        TryAddToMempool(tx_mempool, entry.Fee(fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(built));
        return {hash, fee, size};
    };

    auto split_tx = add_multi_output_spend(COutPoint{txFirst[3]->GetHash(), 0}, 3);
    auto ancestor_low_tx = add_spend(COutPoint{split_tx.hash, 0}, 0, false);
    CAmount two_package_fee = split_tx.fee + ancestor_low_tx.fee;
    uint64_t two_package_size = split_tx.size + ancestor_low_tx.size;

    auto set_block_min_fee = [&](uint64_t fee_per_kvb) {
        Assert(m_node.args)->ForceSetArg("-blockmintxfee", std::to_string(fee_per_kvb));
    };
    uint64_t below_rate = ((two_package_fee * 2 + two_package_size) * 1000) / two_package_size + 1;
    set_block_min_fee(below_rate);
    auto below_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(below_template);
    block = below_template->getBlock();
    BOOST_CHECK(!block_includes(block, split_tx.hash));
    BOOST_CHECK(!block_includes(block, ancestor_low_tx.hash));

    auto ancestor_high_tx = add_spend(COutPoint{ancestor_low_tx.hash, 0}, MEDFEE, false);
    CAmount ancestor_package_fee = two_package_fee + ancestor_high_tx.fee;
    uint64_t ancestor_package_size = two_package_size + ancestor_high_tx.size;
    uint64_t ancestor_rate = (ancestor_package_fee * 1000) / ancestor_package_size;
    set_block_min_fee(ancestor_rate);
    auto ancestor_template = mining->createNewBlock(options, /*cooldown=*/false);
    set_block_min_fee(DEFAULT_BLOCK_MIN_TX_FEE);
    BOOST_REQUIRE(ancestor_template);
    block = ancestor_template->getBlock();
    BOOST_CHECK(block_includes(block, split_tx.hash));
    BOOST_CHECK(block_includes(block, ancestor_low_tx.hash));
    BOOST_CHECK(block_includes(block, ancestor_high_tx.hash));
}

std::vector<CTransactionRef> CreateBigSigOpsCluster(const CTransactionRef& first_tx)
{
    std::vector<CTransactionRef> ret;

    CMutableTransaction tx;
    // block sigops > limit: 1000 CHECKMULTISIG + 1
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_CHECKSIG << OP_1;
    tx.vin[0].prevout.hash = first_tx->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(50);
    for (auto &out : tx.vout) {
        out.nValue = first_tx->vout[0].nValue / 50;
        out.scriptPubKey = CScript() << OP_1;
    }

    tx.vout[0].nValue -= CENT;
    CTransactionRef parent_tx = MakeTransactionRef(tx);
    ret.push_back(parent_tx);
    assert(GetLegacySigOpCount(*parent_tx) == 1);

    // Tx1 has 1 sigops, 1 input, 50 outputs.
    // Tx2-51 has 400 sigops: 1 input, 20 CHECKMULTISIG outputs
    // Total: 1000 CHECKMULTISIG + 1
    for (unsigned int i = 0; i < 50; ++i) {
        auto tx2 = tx;
        tx2.vin.resize(1);
        tx2.vin[0].prevout.hash = parent_tx->GetHash();
        tx2.vin[0].prevout.n = i;
        tx2.vin[0].scriptSig = CScript() << OP_1;
        tx2.vout.resize(20);
        tx2.vout[0].nValue = parent_tx->vout[i].nValue - CENT;
        for (auto &out : tx2.vout) {
            out.nValue = 0;
            out.scriptPubKey = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
        }
        ret.push_back(MakeTransactionRef(tx2));
    }
    return ret;
}

void MinerTestingSetup::TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    Txid hash;
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.nHeight = 11;

    const CAmount BLOCKSUBSIDY = 50 * COIN;
    const CAmount LOWFEE = CENT * 30; // PPC min fee is size-proportional
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4 * COIN;

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // Just to make sure we can still make simple blocks
        auto block_template{mining->createNewBlock(options, /*cooldown=*/false)};
        BOOST_REQUIRE(block_template);
        CBlock block{block_template->getBlock()};

        auto txs = CreateBigSigOpsCluster(txFirst[0]);

        int64_t legacy_sigops = 0;
        for (auto& t : txs) {
            // If we don't set the number of sigops in the CTxMemPoolEntry,
            // template creation fails during sanity checks.
            TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(t));
            legacy_sigops += GetLegacySigOpCount(*t);
            BOOST_CHECK(tx_mempool.GetIter(t->GetHash()).has_value());
        }
        assert(tx_mempool.mapTx.size() == 51);
        assert(legacy_sigops == 20001);
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-blk-sigops"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // Check that the mempool is empty.
        assert(tx_mempool.mapTx.empty());

        // Just to make sure we can still make simple blocks
        auto block_template{mining->createNewBlock(options, /*cooldown=*/false)};
        BOOST_REQUIRE(block_template);
        CBlock block{block_template->getBlock()};

        auto txs = CreateBigSigOpsCluster(txFirst[0]);

        int64_t legacy_sigops = 0;
        for (auto& t : txs) {
            TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).SigOpsCost(GetLegacySigOpCount(*t)*WITNESS_SCALE_FACTOR).FromTx(t));
            legacy_sigops += GetLegacySigOpCount(*t);
            BOOST_CHECK(tx_mempool.GetIter(t->GetHash()).has_value());
        }
        assert(tx_mempool.mapTx.size() == 51);
        assert(legacy_sigops == 20001);

        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // block size > limit
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vout[0].nValue = BLOCKSUBSIDY;
        // 36 * (520char + DROP) + OP_1 = 18757 bytes
        std::vector<unsigned char> vchData(520);
        for (unsigned int i = 0; i < 18; ++i) {
            tx.vin[0].scriptSig << vchData << OP_DROP;
            tx.vout[0].scriptPubKey << vchData << OP_DROP;
        }
        tx.vin[0].scriptSig << OP_1;
        tx.vout[0].scriptPubKey << OP_1;
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout[0].nValue = BLOCKSUBSIDY;
        for (unsigned int i = 0; i < 63; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            hash = tx.GetHash();
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
            BOOST_CHECK(tx_mempool.GetIter(hash).has_value());
            tx.vin[0].prevout.hash = hash;
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // orphan in tx_mempool, template creation fails
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // child with higher feerate than parent
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vin[0].prevout.hash = txFirst[1]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin.resize(2);
        tx.vin[1].scriptSig = CScript() << OP_1;
        tx.vin[1].prevout.hash = txFirst[0]->GetHash();
        tx.vin[1].prevout.n = 0;
        tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE; // First txn output + fresh coinbase - new txn fee
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(HIGHERFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // coinbase in tx_mempool, template creation fails
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
        tx.vout[0].nValue = 0;
        hash = tx.GetHash();
        // give it a fee so it'll get mined
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        // Should throw bad-cb-multiple
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-cb-multiple"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // double spend txn pair in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        tx.vout[0].scriptPubKey = CScript() << OP_1;
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vout[0].scriptPubKey = CScript() << OP_2;
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // subsidy changing
        int nHeight = m_node.chainman->ActiveChain().Height();
        // Create an actual 209999-long block chain (without valid blocks).
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 209999) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));
        // Extend to a 210000-long block chain.
        while (m_node.chainman->ActiveChain().Tip()->nHeight < 210000) {
            CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
            CBlockIndex* next = new CBlockIndex();
            next->phashBlock = new uint256(m_rng.rand256());
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->BuildSkip();
            m_node.chainman->ActiveChain().SetTip(*next);
        }
        BOOST_REQUIRE(mining->createNewBlock(options, /*cooldown=*/false));

        // invalid p2sh txn in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        CScript script = CScript() << OP_0;
        tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options, /*cooldown=*/false), std::runtime_error, HasReason("block-script-verify-flag-failed"));

        // Delete the dummy blocks again.
        while (m_node.chainman->ActiveChain().Tip()->nHeight > nHeight) {
            CBlockIndex* del = m_node.chainman->ActiveChain().Tip();
            m_node.chainman->ActiveChain().SetTip(*Assert(del->pprev));
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(del->pprev->GetBlockHash());
            delete del->phashBlock;
            delete del;
        }
    }

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    // non-final txs in mempool
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
    const int flags{LOCKTIME_VERIFY_SEQUENCE};
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.version = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = m_node.chainman->ActiveChain().Tip()->nHeight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    TryAddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 2, active_chain_tip))); // Sequence locks pass on 2nd block
    }

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()+1-m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    const int SEQUENCE_LOCK_TIME = 512; // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i)
        m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i)->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 1, active_chain_tip)));
    }

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime -= SEQUENCE_LOCK_TIME; // undo tricked MTP
    }

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    hash = tx.GetHash();
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // ensure tx is final for a specific case where there is no locktime and block height is zero
    tx.nLockTime = 0;
    BOOST_CHECK(IsFinalTx(CTransaction(tx), /*nBlockHeight=*/0, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()));

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    TryAddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    auto block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    CBlock block{block_template->getBlock()};
    BOOST_CHECK_EQUAL(block.vtx.size(), 3U);
    // However if we advance height by 1 and time by SEQUENCE_LOCK_TIME, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    }
    m_node.chainman->ActiveChain().Tip()->nHeight++;
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);

    block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_CHECK_EQUAL(block.vtx.size(), 5U);
}

void MinerTestingSetup::TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    TestMemPoolEntryHelper entry;

    struct BuiltTx {
        Txid hash;
        CAmount fee;
    };
    auto add_spend = [&](const COutPoint& prev, CAmount desired_fee, bool spends_coinbase) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) -> BuiltTx {
        CMutableTransaction built;
        built.vin.resize(1);
        built.vin[0].prevout = prev;
        built.vin[0].scriptSig = CScript() << OP_1;
        built.vout.resize(1);
        built.vout[0].scriptPubKey = scriptPubKey;
        CAmount fee = FundTransaction(built, tx_mempool, desired_fee);
        Txid hash = built.GetHash();
        TryAddToMempool(tx_mempool, entry.Fee(fee).Time(Now<NodeSeconds>()).SpendsCoinbase(spends_coinbase).FromTx(built));
        return {hash, fee};
    };
    auto block_includes = [](const CBlock& candidate, const Txid& hash) {
        for (const auto& tx_ref : candidate.vtx) {
            if (tx_ref->GetHash() == hash) return true;
        }
        return false;
    };

    // Test that a tx below the priority threshold but prioritised is included.
    auto free_prioritised_tx = add_spend(COutPoint{txFirst[0]->GetHash(), 0}, 0, true);
    tx_mempool.PrioritiseTransaction(free_prioritised_tx.hash, 5 * COIN);

    // Low fee parent, de-prioritised medium fee tx, and a prioritised child.
    auto parent_tx = add_spend(COutPoint{txFirst[1]->GetHash(), 0}, CENT, true);
    auto medium_fee_tx = add_spend(COutPoint{txFirst[2]->GetHash(), 0}, COIN, true);
    tx_mempool.PrioritiseTransaction(medium_fee_tx.hash, -5 * COIN);
    auto prioritised_child = add_spend(COutPoint{parent_tx.hash, 0}, CENT, false);
    tx_mempool.PrioritiseTransaction(prioritised_child.hash, 2 * COIN);

    // Free chain with prioritised ancestors: FreeParent <- FreeChild <- FreeGrandchild.
    auto free_parent = add_spend(COutPoint{txFirst[3]->GetHash(), 0}, 0, true);
    tx_mempool.PrioritiseTransaction(free_parent.hash, 10 * COIN);
    auto free_child = add_spend(COutPoint{free_parent.hash, 0}, 0, false);
    tx_mempool.PrioritiseTransaction(free_child.hash, 1 * COIN);
    auto free_grandchild = add_spend(COutPoint{free_child.hash, 0}, 0, false);
    tx_mempool.PrioritiseTransaction(free_grandchild.hash, -1 * COIN);

    auto block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};

    BOOST_CHECK(block_includes(block, free_parent.hash));
    BOOST_CHECK(block_includes(block, free_prioritised_tx.hash));
    BOOST_CHECK(block_includes(block, parent_tx.hash));
    BOOST_CHECK(block_includes(block, prioritised_child.hash));
    BOOST_CHECK(block_includes(block, free_child.hash));
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != free_grandchild.hash);
        BOOST_CHECK(block.vtx[i]->GetHash() != medium_fee_tx.hash);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    // Note that by default, these tests run with size accounting enabled.
    CScript scriptPubKey = CScript() << OP_TRUE;
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.include_dummy_extranonce = true;

    // Create and check a simple template
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options, /*cooldown=*/false);
    BOOST_REQUIRE(block_template);
    {
        CBlock block{block_template->getBlock()};
        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "bad-txnmrklroot");
            BOOST_REQUIRE_EQUAL(debug, "hashMerkleRoot mismatch");
        }

        block.hashMerkleRoot = BlockMerkleRoot(block);

        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "");
            BOOST_REQUIRE_EQUAL(debug, "");
        }

        {
            // A block template does not have proof-of-work, but it might pass
            // verification by coincidence. Grind the nonce if needed:
            while (CheckProofOfWork(block.GetHash(), block.nBits, Assert(m_node.chainman)->GetParams().GetConsensus())) {
                block.nNonce++;
            }

            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = true}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "high-hash");
            BOOST_REQUIRE_EQUAL(debug, "proof of work failed");
        }
    }

    // We can't make transactions until we have inputs
    // Therefore, load 110 blocks :)
    static_assert(std::size(BLOCKINFO) == 110, "Should have 110 blocks to import");
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    // peercoin bridge: Bitcoin's hardcoded nonce/extranonce table is incompatible
    // with PPC block hashes. Establish the initial coins with the harness's native
    // regtest block miner.
    for (size_t i = 0; i < std::size(BLOCKINFO); ++i) {
        const int current_height{mining->getTip()->height};
        BlockAssembler::Options block_options;
        block_options.coinbase_output_script = scriptPubKey;
        block_options.include_dummy_extranonce = true;
        CBlock block = BlockAssembler{Assert(m_node.chainman)->ActiveChainstate(), nullptr, block_options}.CreateNewBlock(scriptPubKey)->block;
        node::RegenerateCommitments(block, *Assert(m_node.chainman));
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Assert(m_node.chainman)->GetConsensus())) {
            ++block.nNonce;
        }
        if (txFirst.empty()) baseheight = current_height;
        if (txFirst.size() < 4) txFirst.push_back(block.vtx[0]);
        BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));
        {
            LOCK(cs_main);
            BOOST_REQUIRE_EQUAL(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockHash(), block.GetHash());
        }
        block_template = mining->createNewBlock(options, /*cooldown=*/false);
        BOOST_REQUIRE(block_template);
    }

    LOCK(cs_main);

    TestBasicMining(scriptPubKey, txFirst, baseheight);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPackageSelection(scriptPubKey, txFirst);

    m_node.chainman->ActiveChain().Tip()->nHeight--;
    SetMockTime(0);

    TestPrioritisedMining(scriptPubKey, txFirst);
}

BOOST_AUTO_TEST_SUITE_END()
