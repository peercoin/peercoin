// Copyright (c) 2015-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <random.h>
#include <util.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 2;
    pindexThirdLast.nTime = 1345400368;
    pindexThirdLast.nBits = 0x1c00ffff;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 3;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1345400724;
    pindexSecondLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 4;
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1345400851;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fee3);
}

/* Test the target before v9 */
BOOST_AUTO_TEST_CASE(get_next_work_beforev9)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 2;
    pindexThirdLast.nTime = 1581334360;
    pindexThirdLast.nBits = 0x1c00ffff;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 3;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1581334380;
    pindexSecondLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 4;
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1581334400;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fecc);
}


/* Test the target correct after v9 */
BOOST_AUTO_TEST_CASE(get_next_work_afterv9)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 2;
    pindexThirdLast.nTime = 1588334400;
    pindexThirdLast.nBits = 0x1c00ffff;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 3;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1588334420;
    pindexSecondLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 4;
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1588334440;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00f94c);
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainTrust = i ? blocks[i - 1].nChainTrust + GetBlockTrust(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

BOOST_AUTO_TEST_SUITE_END()
