// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <merkleblock.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <vector>

BOOST_AUTO_TEST_SUITE(merkleblock_tests)

namespace {
CMutableTransaction MakeSimpleTx(uint32_t seed)
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.nTime = seed;
    tx.vin.emplace_back(Txid::FromUint256(uint256{static_cast<unsigned char>(seed)}), 0, CScript() << seed, 0xffffffff);
    tx.vout.emplace_back(CAmount{1000000} + seed, CScript() << seed);
    tx.nLockTime = 0;
    return tx;
}

CBlock MakeSimpleBlock(size_t tx_count, uint32_t seed)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256{static_cast<unsigned char>(seed)};
    block.nTime = seed;
    block.nBits = 0x207fffff;
    block.nNonce = seed;
    block.nFlags = 0;

    block.vtx.reserve(tx_count);
    for (size_t i = 0; i < tx_count; ++i) {
        const uint32_t tx_seed = seed * 100 + static_cast<uint32_t>(i) + 1;
        block.vtx.push_back(MakeTransactionRef(MakeSimpleTx(tx_seed)));
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}
} // namespace

/**
 * Create a CMerkleBlock using a list of txids which will be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_found)
{
    CBlock block = MakeSimpleBlock(9, 1);

    std::set<Txid> txids;
    txids.insert(block.vtx[1]->GetHash());
    txids.insert(block.vtx[8]->GetHash());

    CMerkleBlock merkleBlock(block, txids);

    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());

    // vMatchedTxn is only used when bloom filter is specified.
    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;

    BOOST_CHECK_EQUAL(merkleBlock.txn.ExtractMatches(vMatched, vIndex).GetHex(), block.hashMerkleRoot.GetHex());
    BOOST_CHECK_EQUAL(vMatched.size(), 2U);

    // Ordered by occurrence in depth-first tree traversal.
    BOOST_CHECK_EQUAL(vMatched[0], block.vtx[1]->GetHash());
    BOOST_CHECK_EQUAL(vIndex[0], 1U);

    BOOST_CHECK_EQUAL(vMatched[1], block.vtx[8]->GetHash());
    BOOST_CHECK_EQUAL(vIndex[1], 8U);
}


/**
 * Create a CMerkleBlock using a list of txids which will not be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_not_found)
{
    CBlock block = MakeSimpleBlock(9, 2);

    std::set<Txid> txids;
    txids.insert(Txid::FromUint256(uint256{static_cast<unsigned char>(99)}));

    CMerkleBlock merkleBlock(block, txids);

    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;

    BOOST_CHECK_EQUAL(merkleBlock.txn.ExtractMatches(vMatched, vIndex).GetHex(), block.hashMerkleRoot.GetHex());
    BOOST_CHECK_EQUAL(vMatched.size(), 0U);
    BOOST_CHECK_EQUAL(vIndex.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
