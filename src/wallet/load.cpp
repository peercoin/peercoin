// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/load.h>

#include <common/args.h>
#include <interfaces/chain.h>
#include <scheduler.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

#include <system_error>

using util::Join;

namespace wallet {
// peercoin bridge: v0.16 loaded every wallet found in the wallets directory at startup,
// regardless of persisted -wallet settings. Modern core only loads the explicit settings
// list. Merge both so wallets in the directory keep auto-loading.
static std::vector<std::string> AutoLoadNames(interfaces::Chain& chain, const ArgsManager& args)
{
    std::vector<std::string> names;
    for (const auto& wallet : chain.getSettingsList("wallet")) {
        if (wallet.isStr()) names.push_back(wallet.get_str());
    }
    if (names.empty() && !args.IsArgSet("-wallet")) {
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(GetWalletDir(), ec)) {
            const auto& p = entry.path();
            std::error_code dir_ec;
            if (!entry.is_directory(dir_ec) || dir_ec) continue;

            bool has_database = false;
            for (const auto& filename : {"wallet.cdb", "wallet.dat"}) {
                std::error_code link_ec;
                if (std::filesystem::is_symlink(std::filesystem::symlink_status(p / filename, link_ec))) continue;

                std::error_code file_ec;
                if (std::filesystem::exists(p / filename, file_ec) && !file_ec) {
                    has_database = true;
                    break;
                }
            }
            if (has_database) {
                names.push_back(fs::PathToString(p.filename()));
            }
        }
    }
    return names;
}
bool VerifyWallets(WalletContext& context)
{
    interfaces::Chain& chain = *context.chain;
    ArgsManager& args = *Assert(context.args);

    if (args.IsArgSet("-walletdir")) {
        const fs::path wallet_dir{args.GetPathArg("-walletdir")};
        std::error_code error;
        // The canonical path cleans the path, preventing >1 Berkeley environment instances for the same directory
        // It also lets the fs::exists and fs::is_directory checks below pass on windows, since they return false
        // if a path has trailing slashes, and it strips trailing slashes.
        fs::path canonical_wallet_dir = fs::canonical(wallet_dir, error);
        if (error || !fs::exists(canonical_wallet_dir)) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" does not exist"), fs::PathToString(wallet_dir)));
            return false;
        } else if (!fs::is_directory(canonical_wallet_dir)) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" is not a directory"), fs::PathToString(wallet_dir)));
            return false;
        // The canonical path transforms relative paths into absolute ones, so we check the non-canonical version
        } else if (!wallet_dir.is_absolute()) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" is a relative path"), fs::PathToString(wallet_dir)));
            return false;
        }
        args.ForceSetArg("-walletdir", fs::PathToString(canonical_wallet_dir));
    }

    LogInfo("Using wallet directory %s", fs::PathToString(GetWalletDir()));
    // Print general DB information
    LogDBInfo();

    chain.initMessage(_("Verifying wallet(s)…"));

    // For backwards compatibility if an unnamed top level wallet exists in the
    // wallets directory, include it in the default list of wallets to load.
    if (!args.IsArgSet("wallet")) {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(args, options);
        bilingual_str error_string;
        options.require_existing = true;
        options.verify = false;
        if (MakeWalletDatabase("", options, status, error_string)) {
            common::SettingsValue wallets(common::SettingsValue::VARR);
            wallets.push_back(""); // Default wallet name is ""
            // Pass write=false because no need to write file and probably
            // better not to. If unnamed wallet needs to be added next startup
            // and the setting is empty, this code will just run again.
            chain.overwriteRwSetting("wallet", std::move(wallets), interfaces::SettingsAction::SKIP_WRITE);
        }
    }

    // Keep track of each wallet absolute path to detect duplicates.
    std::set<fs::path> wallet_paths;

    for (const auto& wallet_file : AutoLoadNames(chain, args)) {
        const fs::path path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(wallet_file));

        if (!wallet_paths.insert(path).second) {
            chain.initWarning(strprintf(_("Ignoring duplicate -wallet %s."), wallet_file));
            continue;
        }

        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        options.verify = true;
        bilingual_str error_string;
        if (!MakeWalletDatabase(wallet_file, options, status, error_string)) {
            if (status == DatabaseStatus::FAILED_NOT_FOUND) {
                chain.initWarning(Untranslated(strprintf("Skipping -wallet path that doesn't exist. %s", error_string.original)));
            } else if (status == DatabaseStatus::FAILED_LEGACY_DISABLED) {
                // Skipping legacy wallets as they will not be loaded.
                // This will be properly communicated to the user during the loading process.
                continue;
            } else {
                chain.initError(error_string);
                return false;
            }
        }
    }

    return true;
}

bool LoadWallets(WalletContext& context)
{
    interfaces::Chain& chain = *context.chain;
    try {
        std::set<fs::path> wallet_paths;
        for (const auto& name : AutoLoadNames(chain, *context.args)) {
            if (!wallet_paths.insert(fs::PathFromString(name)).second) {
                continue;
            }
            DatabaseOptions options;
            DatabaseStatus status;
            ReadDatabaseArgs(*context.args, options);
            options.require_existing = true;
            options.verify = false; // No need to verify, assuming verified earlier in VerifyWallets()
            bilingual_str error;
            std::vector<bilingual_str> warnings;
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
            if (!database) {
                if (status == DatabaseStatus::FAILED_NOT_FOUND) continue;
                if (status == DatabaseStatus::FAILED_LEGACY_DISABLED) {
                    // Inform user that legacy wallet is not loaded and suggest upgrade options
                    chain.initWarning(error);
                    continue;
                }
            }
            chain.initMessage(_("Loading wallet…"));
            std::shared_ptr<CWallet> pwallet = database ? CWallet::LoadExisting(context, name, std::move(database), error, warnings) : nullptr;
            if (!warnings.empty()) chain.initWarning(Join(warnings, Untranslated("\n")));
            if (!pwallet) {
                chain.initError(error);
                return false;
            }

            NotifyWalletLoaded(context, pwallet);
            AddWallet(context, pwallet);
        }
        return true;
    } catch (const std::runtime_error& e) {
        chain.initError(Untranslated(e.what()));
        return false;
    }
}

void StartWallets(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        pwallet->postInitProcess();
    }

    context.scheduler->scheduleEvery([&context] { MaybeResendWalletTxs(context); }, 1min);
}

void UnloadWallets(WalletContext& context)
{
    auto wallets = GetWallets(context);
    while (!wallets.empty()) {
        auto wallet = wallets.back();
        wallets.pop_back();
        std::vector<bilingual_str> warnings;
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt, warnings);
        WaitForDeleteWallet(std::move(wallet));
    }
}
} // namespace wallet
