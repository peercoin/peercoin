// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <key.h>
#include <policy/fees/block_policy_estimator.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(max_signed_input_size_uses_external_outpoint)
{
    const CKey key{GenerateRandomKey()};
    FillableSigningProvider provider;
    BOOST_REQUIRE(provider.AddKey(key));

    const CTxOut txout{COIN, GetScriptForDestination(PKHash{key.GetPubKey()})};
    const COutPoint outpoint{Txid{}, 0};
    CCoinControl coin_control;
    coin_control.Select(outpoint).SetTxOut(txout);

    const int low_r{CalculateMaximumSignedInputSize(txout, COutPoint{}, &provider, /*can_grind_r=*/true, &coin_control)};
    const int high_r{CalculateMaximumSignedInputSize(txout, outpoint, &provider, /*can_grind_r=*/true, &coin_control)};
    BOOST_CHECK_EQUAL(high_r, low_r + 1);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // peercoin bridge: subtract-from-recipient transactions keep the requested
    // recipient output value intact and return any leftover to a separate change
    // output owned by the wallet, rather than merging change into the recipient.
    // The fee is charged to the inputs, not folded into the recipient output.
    auto check_tx = [&wallet](CAmount leftover_input_amount) -> std::pair<CAmount, CAmount> {
        CRecipient recipient{PubKeyDestination({}), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_GT(txr.fee, 0);
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 2);
        BOOST_CHECK(std::any_of(txr.tx->vout.begin(), txr.tx->vout.end(),
                                [&recipient](const CTxOut& out) { return out.nValue == recipient.nAmount; }));
        CAmount total_out{0};
        for (const auto& out : txr.tx->vout) total_out += out.nValue;
        return {txr.fee, total_out};
    };

    const auto [fee, total0]{check_tx(0)};
    const auto [fee1, total1]{check_tx(123)};
    BOOST_CHECK_EQUAL(fee, fee1);
    BOOST_CHECK_EQUAL(total0, total1);

    const auto [fee2, total2]{check_tx(fee)};
    BOOST_CHECK_EQUAL(fee, fee2);
    BOOST_CHECK_EQUAL(total0, total2);

    const auto [fee3, total3]{check_tx(fee + 123)};
    BOOST_CHECK_EQUAL(fee, fee3);
    BOOST_CHECK_EQUAL(total0, total3);
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // peercoin bridge: PoW subsidy is difficulty-dependent (~99.99 PPC/regtest
    // block here), so the exact balance is measured rather than hardcoded.
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    BOOST_CHECK_GE(coins.size(), 4);
    // Preselect the first 3 UTXO.
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than the wallet can cover.
    CAmount wallet_total{0};
    for (const auto& c : coins) wallet_total += c.txout.nValue;

    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/wallet_total + COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Requesting more than the total available balance must fail even with
    // subtract-from-recipient enabled; if preset inputs were double-counted the
    // wallet might silently fund a short transaction instead.
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
