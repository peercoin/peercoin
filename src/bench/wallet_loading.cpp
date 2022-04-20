// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <interfaces/chain.h>
#include <node/context.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <test/util/wallet.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/wallet.h>

#include <optional>

using wallet::CWallet;
using wallet::DatabaseOptions;
using wallet::DatabaseStatus;
using wallet::ISMINE_SPENDABLE;
using wallet::MakeWalletDatabase;
using wallet::TxStateInactive;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WalletContext;

static const std::shared_ptr<CWallet> BenchLoadWallet(WalletContext& context, DatabaseOptions& options)
{
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    assert(database);
    auto wallet = CWallet::Create(context, "", std::move(database), options.create_flags, error, warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

static void BenchUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    SyncWithValidationInterfaceQueue();
    wallet->m_chain_notifications_handler.reset();
    UnloadWallet(std::move(wallet));
}

static void AddTx(CWallet& wallet)
{
    bilingual_str error;
    CTxDestination dest;
    wallet.GetNewDestination(OutputType::BECH32, "", dest, error);

    CMutableTransaction mtx;
    mtx.vout.push_back({COIN, GetScriptForDestination(dest)});
    mtx.vin.push_back(CTxIn());

    wallet.AddToWallet(MakeTransactionRef(mtx), TxStateInactive{});
}

static void WalletLoading(benchmark::Bench& bench, bool legacy_wallet)
{
    const auto test_setup = MakeNoLogFileContext<TestingSetup>();
    test_setup->m_args.ForceSetArg("-unsafesqlitesync", "1");

    WalletContext context;
    context.args = &test_setup->m_args;
    context.chain = test_setup->m_node.chain.get();

    // Setup the wallet
    // Loading the wallet will also create it
    DatabaseOptions options;
    if (!legacy_wallet) options.create_flags = WALLET_FLAG_DESCRIPTORS;
    auto wallet = BenchLoadWallet(context, options);

    // Generate a bunch of transactions and addresses to put into the wallet
    for (int i = 0; i < 5000; ++i) {
        AddTx(*wallet);
    }

    // reload the wallet for the actual benchmark
    BenchUnloadWallet(std::move(wallet));

    bench.epochs(5).run([&] {
        wallet = BenchLoadWallet(context, options);

        // Cleanup
        BenchUnloadWallet(std::move(wallet));
    });
}

static void WalletLoadingLegacy(benchmark::Bench& bench) { WalletLoading(bench, /*legacy_wallet=*/true); }
static void WalletLoadingDescriptors(benchmark::Bench& bench) { WalletLoading(bench, /*legacy_wallet=*/false); }

BENCHMARK(WalletLoadingLegacy);
BENCHMARK(WalletLoadingDescriptors);
