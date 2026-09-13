// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>

#include <clientversion.h>
#include <common/system.h>
#include <consensus/merkle.h>
#include <key.h>
#include <key_io.h>
#include <merkleblock.h>
#include <primitives/block.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

namespace bloom_tests {
struct BloomTest : public BasicTestingSetup {
    std::vector<unsigned char> RandomData();
};

static std::vector<unsigned char> FixedBytes(size_t len, unsigned char value)
{
    return std::vector<unsigned char>(len, value);
}

static std::vector<unsigned char> ValidPubKey()
{
    return {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55,
        0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc,
        0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98
    };
}

static CScript PubKeyScript(unsigned char id)
{
    return CScript() << ValidPubKey() << OP_CHECKSIG;
}

static CScript PubKeyHashScript(unsigned char id)
{
    return CScript() << OP_DUP << OP_HASH160 << FixedBytes(20, id) << OP_EQUALVERIFY << OP_CHECKSIG;
}

static CScript InputScript(unsigned char id)
{
    return CScript() << FixedBytes(73, id);
}

static CMutableTransaction MakeTx(uint32_t seed, const CScript& out_script)
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.nTime = seed;
    tx.vin.emplace_back(Txid::FromUint256(uint256{static_cast<unsigned char>(seed)}), 0, InputScript(static_cast<unsigned char>(seed)), 0xffffffff);
    tx.vout.emplace_back(CAmount{1000000} + seed, out_script);
    tx.nLockTime = 0;
    return tx;
}

static CMutableTransaction MakeSpendingTx(uint32_t seed, const CTransaction& spent)
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.nTime = seed;
    tx.vin.emplace_back(spent.GetHash(), 0, InputScript(static_cast<unsigned char>(seed)), 0xffffffff);
    tx.vout.emplace_back(CAmount{1000000} + seed, PubKeyHashScript(static_cast<unsigned char>(seed)));
    tx.nLockTime = 0;
    return tx;
}

static CBlock MakeBlock(std::vector<CTransactionRef> vtx, uint32_t seed)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256{static_cast<unsigned char>(seed)};
    block.nTime = seed;
    block.nBits = 0x207fffff;
    block.nNonce = seed;
    block.nFlags = 0;
    block.vtx = std::move(vtx);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}
} // namespace bloom_tests

using namespace bloom_tests;

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BloomTest)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    BOOST_CHECK_MESSAGE( !filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter should be empty!");
    filter.insert("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8);
    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains("19108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter contains something it shouldn't!");

    filter.insert("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"03614e9b050000000000000001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8);
    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains("19108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter contains something it shouldn't!");

    filter.insert("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"03ce4299050000000100008001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    std::string strSecret = std::string("7AaxPXrVSjrn94fVFhQPW3e23JdbLfm5rt33iSPVESSn3bwv4DR");
    CKey key = DecodeSecret(strSecret);
    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(hash);

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"038fc16b080000000000000001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    CTransaction tx{MakeTx(1, PubKeyHashScript(1))};
    CTransaction spending_tx{MakeSpendingTx(2, tx)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(tx.GetHash().ToUint256());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(FixedBytes(20, 1));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Bloom filter didn't match P2PKH output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(FixedBytes(20, 1));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spending_tx), "Bloom filter didn't match spent output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(tx.vin[0].prevout);
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256{static_cast<unsigned char>(99)});
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Bloom filter matched unrelated tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(FixedBytes(20, 99));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Bloom filter matched unrelated address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint{tx.vin[0].prevout.hash, 1});
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Bloom filter matched unused output");
}

BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    std::vector<CTransactionRef> vtx;
    for (uint32_t i = 0; i < 12; ++i) {
        vtx.push_back(MakeTransactionRef(MakeTx(i + 1, PubKeyHashScript(static_cast<unsigned char>(i + 1)))));
    }
    CBlock block{MakeBlock(std::move(vtx), 1)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    filter.insert(block.vtx[7]->GetHash().ToUint256());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.header.GetHash().GetHex(), block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 1U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 7U);
    BOOST_CHECK(merkle_block.vMatchedTxn[0].second == block.vtx[7]->GetHash());

    std::vector<Txid> v_matched;
    std::vector<unsigned int> v_index;
    BOOST_CHECK_EQUAL(merkle_block.txn.ExtractMatches(v_matched, v_index), block.hashMerkleRoot);

    filter.insert(block.vtx[8]->GetHash().ToUint256());
    merkle_block = CMerkleBlock(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 2U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 7U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[1].first, 8U);
    BOOST_CHECK(merkle_block.txn.ExtractMatches(v_matched, v_index) == block.hashMerkleRoot);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction spend{MakeSpendingTx(2, gen)};
    CTransaction other{MakeTx(3, PubKeyHashScript(3))};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(spend),
        MakeTransactionRef(other),
    };
    CBlock block{MakeBlock(std::move(vtx), 2)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ValidPubKey());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 2U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[1].first, 1U);
    BOOST_CHECK(filter.contains(COutPoint{gen.GetHash(), 0}));
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction spend{MakeSpendingTx(2, gen)};
    CTransaction other{MakeTx(3, PubKeyHashScript(3))};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(spend),
        MakeTransactionRef(other),
    };
    CBlock block{MakeBlock(std::move(vtx), 3)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    filter.insert(ValidPubKey());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 1U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);
    BOOST_CHECK(!filter.contains(COutPoint{gen.GetHash(), 0}));
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction other{MakeTx(2, PubKeyHashScript(2))};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(other),
    };
    CBlock block{MakeBlock(std::move(vtx), 4)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(gen.GetHash().ToUint256());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.header.GetHash().GetHex(), block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 1U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);

    CDataStream merkle_stream{SER_NETWORK, PROTOCOL_VERSION};
    merkle_stream << merkle_block;

    CMerkleBlock deserialized;
    SpanReader reader{MakeUCharSpan(merkle_stream)};
    reader >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.header.GetHash().GetHex(), merkle_block.header.GetHash().GetHex());
    std::vector<Txid> v_matched;
    std::vector<unsigned int> v_index;
    BOOST_CHECK_EQUAL(deserialized.txn.ExtractMatches(v_matched, v_index), block.hashMerkleRoot);
}

BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction p2pkh{MakeTx(2, PubKeyHashScript(2))};
    CTransaction spend{MakeSpendingTx(3, p2pkh)};
    CTransaction other{MakeTx(4, PubKeyHashScript(4))};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(p2pkh),
        MakeTransactionRef(spend),
        MakeTransactionRef(other),
    };
    CBlock block{MakeBlock(std::move(vtx), 5)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(gen.GetHash().ToUint256());
    filter.insert(p2pkh.GetHash().ToUint256());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 2U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[1].first, 1U);

    std::vector<Txid> v_matched;
    std::vector<unsigned int> v_index;
    BOOST_CHECK_EQUAL(merkle_block.txn.ExtractMatches(v_matched, v_index), block.hashMerkleRoot);
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction p2pkh{MakeTx(2, PubKeyHashScript(2))};
    CTransaction spend{MakeSpendingTx(3, p2pkh)};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(p2pkh),
        MakeTransactionRef(spend),
    };
    CBlock block{MakeBlock(std::move(vtx), 6)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    filter.insert(ValidPubKey());
    filter.insert(FixedBytes(20, 2));

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 2U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[1].first, 1U);
    BOOST_CHECK(filter.contains(COutPoint{gen.GetHash(), 0}));
    BOOST_CHECK(!filter.contains(COutPoint{p2pkh.GetHash(), 0}));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    CTransaction gen{MakeTx(1, PubKeyScript(1))};
    CTransaction p2pkh{MakeTx(2, PubKeyHashScript(2))};
    CTransaction spend{MakeSpendingTx(3, p2pkh)};

    std::vector<CTransactionRef> vtx{
        MakeTransactionRef(gen),
        MakeTransactionRef(p2pkh),
        MakeTransactionRef(spend),
    };
    CBlock block{MakeBlock(std::move(vtx), 7)};

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    filter.insert(ValidPubKey());
    filter.insert(FixedBytes(20, 2));

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn.size(), 2U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[0].first, 0U);
    BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[1].first, 1U);
    BOOST_CHECK(!filter.contains(COutPoint{gen.GetHash(), 0}));
    BOOST_CHECK(!filter.contains(COutPoint{p2pkh.GetHash(), 0}));
}

std::vector<unsigned char> BloomTest::RandomData()
{
    uint256 r = m_rng.rand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    SeedRandomForTest(SeedRand::ZEROS);

    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Expect about 100 hits
    BOOST_CHECK_EQUAL(nHits, 71U);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives
    BOOST_CHECK_EQUAL(nHits, 3U);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
