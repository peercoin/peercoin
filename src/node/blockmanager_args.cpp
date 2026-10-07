// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockmanager_args.h>

#include <common/args.h>
#include <node/blockstorage.h>
#include <node/database_args.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/translation.h>
#include <validation.h>

#include <cstdint>

namespace node {
util::Result<void> ApplyArgsManOptions(const ArgsManager& args, BlockManager::Options& opts)
{
    if (auto value{args.GetBoolArg("-blocksxor")}) opts.use_xor = *value;
    int64_t nPruneArg{args.GetIntArg("-prune", opts.prune_target)};
    if (nPruneArg != 0) {
        return util::Error{_("Block pruning is not supported by Peercoin.")};
    }
    opts.prune_target = 0;

    if (auto value{args.GetBoolArg("-fastprune")}) opts.fast_prune = *value;

    ReadDatabaseArgs(args, opts.block_tree_db_params.options);

    return {};
}
} // namespace node
