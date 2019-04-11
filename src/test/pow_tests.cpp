// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <random.h>
#include <util/system.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
/* real blocks used */
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

BOOST_AUTO_TEST_CASE(get_next_work_beforev9pos)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexFourthLast;
    pindexFourthLast.nHeight = 2;
    pindexFourthLast.nTime = 1581334400;
    pindexFourthLast.nBits = 0x1c00ffff;

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 3;
    pindexThirdLast.pprev = &pindexFourthLast;
    pindexThirdLast.nTime = 1581334420;
    pindexThirdLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 4;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1581334440;
    pindexSecondLast.nBits = 0x1c00ff4a;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 5;
    pindexLast.SetProofOfStake();
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1581334441;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fe4b);
}

BOOST_AUTO_TEST_CASE(get_next_work_beforev9pos2)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexFourthLast;
    pindexFourthLast.nHeight = 2;
    pindexFourthLast.nTime = 1581334400;
    pindexFourthLast.nBits = 0x1c00ffff;

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 3;
    pindexThirdLast.pprev = &pindexFourthLast;
    pindexThirdLast.nTime = 1581334420;
    pindexThirdLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 4;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1581334440;
    pindexSecondLast.nBits = 0x1c00ff4a;

    CBlockIndex pindexPos;
    pindexPos.nHeight = 5;
    pindexPos.SetProofOfStake();
    pindexPos.pprev = &pindexSecondLast;
    pindexPos.nTime = 1581334441;
    pindexPos.nBits = 0x1c00ff4a;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 6;
    pindexLast.SetProofOfStake();
    pindexLast.pprev = &pindexPos;
    pindexLast.nTime = 1581334442;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fdca);
}


/* Test the target correct after v9 */
BOOST_AUTO_TEST_CASE(get_next_work_afterv9)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 2;
    pindexThirdLast.SetProofOfStake();
    pindexThirdLast.nTime = 1598334400;
    pindexThirdLast.nBits = 0x1c00ffff;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 3;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1598334420;
    pindexSecondLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 4;
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1598334440;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fc48);
}

BOOST_AUTO_TEST_CASE(get_next_work_afterv9pos)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexFourthLast;
    pindexFourthLast.nHeight = 2;
    pindexFourthLast.SetProofOfStake();
    pindexFourthLast.nTime = 1598334400;
    pindexFourthLast.nBits = 0x1c00ffff;

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 3;
    pindexThirdLast.pprev = &pindexFourthLast;
    pindexThirdLast.nTime = 1598334420;
    pindexThirdLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 4;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1598334440;
    pindexSecondLast.nBits = 0x1c00ff4a;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 5;
    pindexLast.SetProofOfStake();
    pindexLast.pprev = &pindexSecondLast;
    pindexLast.nTime = 1598334441;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fc48);
}

BOOST_AUTO_TEST_CASE(get_next_work_afterv9pos2)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexFourthLast;
    pindexFourthLast.nHeight = 2;
    pindexFourthLast.SetProofOfStake();
    pindexFourthLast.nTime = 1598334400;
    pindexFourthLast.nBits = 0x1c00ffff;

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 3;
    pindexThirdLast.pprev = &pindexFourthLast;
    pindexThirdLast.nTime = 1598334420;
    pindexThirdLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 4;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1598334440;
    pindexSecondLast.nBits = 0x1c00ff4a;

    CBlockIndex pindexPos;
    pindexPos.nHeight = 5;
    pindexPos.SetProofOfStake();
    pindexPos.pprev = &pindexSecondLast;
    pindexPos.nTime = 1598334441;
    pindexPos.nBits = 0x1c00ff4a;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 6;
    pindexLast.SetProofOfStake();
    pindexLast.pprev = &pindexPos;
    pindexLast.nTime = 1598334442;
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fc48);
}

BOOST_AUTO_TEST_CASE(get_next_work_afterv9pos7200)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindexFourthLast;
    pindexFourthLast.nHeight = 2;
    pindexFourthLast.SetProofOfStake();
    pindexFourthLast.nTime = 1598334400;
    pindexFourthLast.nBits = 0x1c00ffff;

    CBlockIndex pindexThirdLast;
    pindexThirdLast.nHeight = 3;
    pindexThirdLast.pprev = &pindexFourthLast;
    pindexThirdLast.nTime = 1598334420;
    pindexThirdLast.nBits = 0x1c00ff7f;

    CBlockIndex pindexSecondLast;
    pindexSecondLast.nHeight = 4;
    pindexSecondLast.pprev = &pindexThirdLast;
    pindexSecondLast.nTime = 1598334440;
    pindexSecondLast.nBits = 0x1c00ff4a;

    CBlockIndex pindexPos;
    pindexPos.nHeight = 5;
    pindexPos.SetProofOfStake();
    pindexPos.pprev = &pindexSecondLast;
    pindexPos.nTime = 1598334441;
    pindexPos.nBits = 0x1c00ff4a;

    CBlockIndex pindexLast;
    pindexLast.nHeight = 6;
    pindexLast.SetProofOfStake();
    pindexLast.pprev = &pindexPos;
    pindexLast.nTime = 1598344442; // 10001 seconds after block 5
    pindexLast.nBits = 0x1c00ff4a;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexLast, false, chainParams->GetConsensus()), 0x1c00fc48);

    CBlockIndex pindexNext;
    pindexNext.nHeight = 7;
    pindexNext.pprev = &pindexLast;
    pindexNext.nTime = 1598344460;
    pindexNext.nBits = 0x1c00fc48;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindexNext, false, chainParams->GetConsensus()), 0x1c01019b);
}

BOOST_AUTO_TEST_CASE(get_next_work_beforev9real)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindex495492;
    pindex495492.nHeight = 495492;
    pindex495492.SetProofOfStake();
    pindex495492.nTime = 1588163347;
    pindex495492.nBits = 0x1c1ee519;

    CBlockIndex pindex495493;
    pindex495493.nHeight = 495493;
    pindex495493.pprev = &pindex495492;
    pindex495493.nTime = 1588163674;
    pindex495493.nBits = 0x19023c6a;

    CBlockIndex pindex495494;
    pindex495494.nHeight = 495494;
    pindex495494.SetProofOfStake();
    pindex495494.pprev = &pindex495493;
    pindex495494.nTime = 1588164450;
    pindex495494.nBits = 0x1c1ef882;

    CBlockIndex pindex495495;
    pindex495495.nHeight = 495495;
    pindex495495.pprev = &pindex495494;
    pindex495495.nTime = 1588164933;
    pindex495495.nBits = 0x19024189;

    CBlockIndex pindex495496;
    pindex495496.nHeight = 495496;
    pindex495496.SetProofOfStake();
    pindex495496.pprev = &pindex495495;
    pindex495496.nTime = 1588164959;
    pindex495496.nBits = 0x1c1f05ae;

    CBlockIndex pindex495497;
    pindex495497.nHeight = 495497;
    pindex495497.SetProofOfStake();
    pindex495497.pprev = &pindex495496;
    pindex495497.nTime = 1588165390;
    pindex495497.nBits = 0x1c1f034a;

    CBlockIndex pindex495498;
    pindex495498.nHeight = 495498;
    pindex495498.SetProofOfStake();
    pindex495498.pprev = &pindex495497;
    pindex495498.nTime = 1588165829;
    pindex495498.nBits = 0x1c1efedb;

    CBlockIndex pindex495499;
    pindex495499.nHeight = 495499;
    pindex495499.SetProofOfStake();
    pindex495499.pprev = &pindex495498;
    pindex495499.nTime = 1588165881;
    pindex495499.nBits = 0x1c1efaa2;

    CBlockIndex pindex495500;
    pindex495500.nHeight = 495500;
    pindex495500.SetProofOfStake();
    pindex495500.pprev = &pindex495499;
    pindex495500.nTime = 1588169146;
    pindex495500.nBits = 0x1c1eec46;

    CBlockIndex pindex495501;
    pindex495501.nHeight = 495501;
    pindex495501.SetProofOfStake();
    pindex495501.pprev = &pindex495500;
    pindex495501.nTime = 1588170378;
    pindex495501.nBits = 0x1c1f31f8;

    CBlockIndex pindex495502;
    pindex495502.nHeight = 495502;
    pindex495502.SetProofOfStake();
    pindex495502.pprev = &pindex495501;
    pindex495502.nTime = 1588170817;
    pindex495502.nBits = 0x1c1f42a4;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495502, false, chainParams->GetConsensus()), 0x19023ad3);

    CBlockIndex pindex495503;
    pindex495503.nHeight = 495503;
    pindex495503.pprev = &pindex495502;
    pindex495503.nTime = 1588170876;
    pindex495503.nBits = 0x19023ad3;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495503, false, chainParams->GetConsensus()), 0x190244e6);

    CBlockIndex pindex495504;
    pindex495504.nHeight = 495504;
    pindex495504.pprev = &pindex495503;
    pindex495504.nTime = 1588171246;
    pindex495504.nBits = 0x190244e6;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495504, false, chainParams->GetConsensus()), 0x19024475);

    CBlockIndex pindex495505;
    pindex495505.nHeight = 495505;
    pindex495505.pprev = &pindex495504;
    pindex495505.nTime = 1588171256;
    pindex495505.nBits = 0x19024475;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495505, false, chainParams->GetConsensus()), 0x19024353);

    CBlockIndex pindex495506;
    pindex495506.nHeight = 495506;
    pindex495506.pprev = &pindex495505;
    pindex495506.nTime = 1588171290;
    pindex495506.nBits = 0x19024353;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495506, false, chainParams->GetConsensus()), 0x1902423d);
}


BOOST_AUTO_TEST_CASE(get_next_work_afterv9real)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    CBlockIndex pindex495492;
    pindex495492.nHeight = 495492;
    pindex495492.SetProofOfStake();
    pindex495492.nTime = 1598163347;
    pindex495492.nBits = 0x1c1ee519;

    CBlockIndex pindex495493;
    pindex495493.nHeight = 495493;
    pindex495493.pprev = &pindex495492;
    pindex495493.nTime = 1598163674;
    pindex495493.nBits = 0x19023c6a;

    CBlockIndex pindex495494;
    pindex495494.nHeight = 495494;
    pindex495494.SetProofOfStake();
    pindex495494.pprev = &pindex495493;
    pindex495494.nTime = 1598164450;
    pindex495494.nBits = 0x1c1ef882;

    CBlockIndex pindex495495;
    pindex495495.nHeight = 495495;
    pindex495495.pprev = &pindex495494;
    pindex495495.nTime = 1598164933;
    pindex495495.nBits = 0x19024189;

    CBlockIndex pindex495496;
    pindex495496.nHeight = 495496;
    pindex495496.SetProofOfStake();
    pindex495496.pprev = &pindex495495;
    pindex495496.nTime = 1598164959;
    pindex495496.nBits = 0x1c1f05ae;

    CBlockIndex pindex495497;
    pindex495497.nHeight = 495497;
    pindex495497.SetProofOfStake();
    pindex495497.pprev = &pindex495496;
    pindex495497.nTime = 1598165390;
    pindex495497.nBits = 0x1c1f034a;

    CBlockIndex pindex495498;
    pindex495498.nHeight = 495498;
    pindex495498.SetProofOfStake();
    pindex495498.pprev = &pindex495497;
    pindex495498.nTime = 1598165829;
    pindex495498.nBits = 0x1c1efedb;

    CBlockIndex pindex495499;
    pindex495499.nHeight = 495499;
    pindex495499.SetProofOfStake();
    pindex495499.pprev = &pindex495498;
    pindex495499.nTime = 1598165881;
    pindex495499.nBits = 0x1c1efaa2;

    CBlockIndex pindex495500;
    pindex495500.nHeight = 495500;
    pindex495500.SetProofOfStake();
    pindex495500.pprev = &pindex495499;
    pindex495500.nTime = 1598169146;
    pindex495500.nBits = 0x1c1eec46;

    CBlockIndex pindex495501;
    pindex495501.nHeight = 495501;
    pindex495501.SetProofOfStake();
    pindex495501.pprev = &pindex495500;
    pindex495501.nTime = 1598170378;
    pindex495501.nBits = 0x1c1f31f8;

    CBlockIndex pindex495502;
    pindex495502.nHeight = 495502;
    pindex495502.SetProofOfStake();
    pindex495502.pprev = &pindex495501;
    pindex495502.nTime = 1598170817;
    pindex495502.nBits = 0x1c1f42a4;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495502, false, chainParams->GetConsensus()), 0x19023d17); // was 0x19023ad3

    CBlockIndex pindex495503;
    pindex495503.nHeight = 495503;
    pindex495503.pprev = &pindex495502;
    pindex495503.nTime = 1598170876;
    pindex495503.nBits = 0x19023d17;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495503, false, chainParams->GetConsensus()), 0x19024180); // was 0x190244e6

    CBlockIndex pindex495504;
    pindex495504.nHeight = 495504;
    pindex495504.pprev = &pindex495503;
    pindex495504.nTime = 1598171246;
    pindex495504.nBits = 0x19024180;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495504, false, chainParams->GetConsensus()), 0x19023b5e); //was 0x19024475

    CBlockIndex pindex495505;
    pindex495505.nHeight = 495505;
    pindex495505.pprev = &pindex495504;
    pindex495505.nTime = 1598171256;
    pindex495505.nBits = 0x19023b5e;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495505, false, chainParams->GetConsensus()), 0x1902349f); // was 0x19024353

    CBlockIndex pindex495506;
    pindex495506.nHeight = 495506;
    pindex495506.pprev = &pindex495505;
    pindex495506.nTime = 1598171290;
    pindex495506.nBits = 0x1902349f;

    BOOST_CHECK_EQUAL(GetNextTargetRequired(&pindex495506, false, chainParams->GetConsensus()), 0x19022e00); // was 0x1902423d
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
