// Copyright (c) 2026 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <kernel.h>
#include <uint256.h>

#include <array>
#include <optional>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(peercoin_kernel_tests)

BOOST_AUTO_TEST_CASE(stake_kernel_hash_inputs)
{
    Kernel::StakeKernelHashInputs inputs;
    inputs.nBits = 0x1d00ffff;
    inputs.nStakeModifier = 0x0123456789abcdef;
    inputs.nTimeBlockFrom = 1345083810;
    inputs.nTxPrevOffset = 81;
    inputs.nTimeTxPrev = 1345083811;
    inputs.nPrevOutput = 2;
    inputs.nTimeTx = 1345084000;

    inputs.use_stake_modifier = false;
    BOOST_CHECK_EQUAL(inputs.GetHash().GetHex(), "def5d5f23e4e056de312044a9ff6e58ba48102e78dd0341ee64c0b07a338c00c");

    inputs.use_stake_modifier = true;
    BOOST_CHECK_EQUAL(inputs.GetHash().GetHex(), "0a0fd531f2108cd00ff595039afc1b0b77dba6a35bb016908f598070e58e2fe7");
}

BOOST_AUTO_TEST_CASE(protocol_activation_boundaries)
{
    struct ActivationCase {
        Kernel::Protocol protocol;
        uint32_t main_time;
        uint32_t test_time;
        std::optional<int> main_height;
        std::optional<int> test_height;
        bool regtest_always;
    };

    const std::array activations{
        ActivationCase{Kernel::Protocol::V03,   1363800000, 1359781000, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::V04,   1399300000, 1395700000, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::V05,   1461700000, 1447700000, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::V06,   1513050000, 1508198400, 339678,       301251,       true},
        ActivationCase{Kernel::Protocol::V07,   1552392000, 1541505600, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::BTC16, 1569931200, 1554811200, std::nullopt, std::nullopt, true},
        ActivationCase{Kernel::Protocol::V09,   1591617600, 1581940800, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::V10,   1635768000, 1625140800, std::nullopt, std::nullopt, false},
        ActivationCase{Kernel::Protocol::V12,   1700276331, 1671060214, std::nullopt, std::nullopt, true},
        ActivationCase{Kernel::Protocol::V14,   1717416000, 1710720000, 770395,       573706,       true},
        ActivationCase{Kernel::Protocol::V15,   1741780800, 1734004800, 801330,       612775,       true},
    };

    for (const auto& activation : activations) {
        const auto check_schedule = [&](ChainType chain_type, uint32_t switch_time,
                                        std::optional<int> switch_height) {
            const std::optional<int> active_height{
                switch_height ? std::optional<int>{*switch_height + 1} : std::nullopt};
            BOOST_CHECK(!Kernel::IsProtocolActive(activation.protocol, chain_type,
                                                  switch_time - 1, active_height));
            if (switch_height) {
                BOOST_CHECK(!Kernel::IsProtocolActive(activation.protocol, chain_type,
                                                      switch_time, switch_height));
                BOOST_CHECK(Kernel::IsProtocolActive(activation.protocol, chain_type,
                                                     switch_time, active_height));
                BOOST_CHECK(!Kernel::IsProtocolActive(activation.protocol, chain_type, switch_time));
            } else {
                BOOST_CHECK(Kernel::IsProtocolActive(activation.protocol, chain_type, switch_time));
            }
        };

        check_schedule(ChainType::MAIN, activation.main_time, activation.main_height);
        check_schedule(ChainType::TESTNET, activation.test_time, activation.test_height);
        check_schedule(ChainType::TESTNET4, activation.test_time, activation.test_height);
        check_schedule(ChainType::SIGNET, activation.test_time, activation.test_height);

        if (activation.regtest_always) {
            BOOST_CHECK(Kernel::IsProtocolActive(activation.protocol, ChainType::REGTEST, 0));
        } else {
            check_schedule(ChainType::REGTEST, activation.test_time, activation.test_height);
        }
    }
}

BOOST_AUTO_TEST_CASE(stake_modifier_v03_active_and_side_chain_traversal)
{
    std::array<CBlockIndex, 7> active_blocks;
    for (size_t i = 0; i < active_blocks.size(); ++i) {
        active_blocks[i].nHeight = i;
        active_blocks[i].nTime = i * 100;
        active_blocks[i].pprev = i == 0 ? nullptr : &active_blocks[i - 1];
    }
    CChain active_chain;
    active_chain.SetTip(active_blocks.back());

    active_blocks[4].SetStakeModifier(44, true);
    BOOST_CHECK_EQUAL(Kernel::FindStakeModifierV03(active_blocks[1], active_blocks[6], active_chain, 250),
                      &active_blocks[4]);

    std::array<CBlockIndex, 4> side_blocks;
    for (size_t i = 0; i < side_blocks.size(); ++i) {
        side_blocks[i].nHeight = i + 3;
        side_blocks[i].nTime = (i + 3) * 100;
        side_blocks[i].pprev = i == 0 ? &active_blocks[2] : &side_blocks[i - 1];
    }

    // The candidate tip must be considered; the former temporary-chain index
    // traversal stopped just before processing this block.
    side_blocks[3].SetStakeModifier(66, true);
    BOOST_CHECK_EQUAL(Kernel::FindStakeModifierV03(active_blocks[1], side_blocks[3], active_chain, 250),
                      &side_blocks[3]);

    // When several side-chain modifiers qualify, select the oldest one.
    side_blocks[1].SetStakeModifier(44, true);
    BOOST_CHECK_EQUAL(Kernel::FindStakeModifierV03(active_blocks[1], side_blocks[3], active_chain, 250),
                      &side_blocks[1]);

    // A branch joining after an eligible active-chain modifier uses the active
    // prefix before entering the side chain.
    std::array<CBlockIndex, 2> late_fork;
    for (size_t i = 0; i < late_fork.size(); ++i) {
        late_fork[i].nHeight = i + 5;
        late_fork[i].nTime = (i + 5) * 100;
        late_fork[i].pprev = i == 0 ? &active_blocks[4] : &late_fork[i - 1];
    }
    BOOST_CHECK_EQUAL(Kernel::FindStakeModifierV03(active_blocks[1], late_fork[1], active_chain, 250),
                      &active_blocks[4]);
}

BOOST_AUTO_TEST_SUITE_END()
