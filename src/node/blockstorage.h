// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKSTORAGE_H
#define BITCOIN_NODE_BLOCKSTORAGE_H

#include <fs.h>
#include <protocol.h> // For CMessageHeader::MessageStartChars
#include <sync.h>
#include <txdb.h>

#include <atomic>
#include <cstdint>
#include <vector>

extern RecursiveMutex cs_main;

class ArgsManager;
class BlockValidationState;
class CBlock;
class CBlockFileInfo;
class CBlockIndex;
class CBlockUndo;
class CChain;
class CChainParams;
class CChainState;
class ChainstateManager;
struct CCheckpointData;
struct FlatFilePos;
namespace Consensus {
struct Params;
}

namespace node {
static constexpr bool DEFAULT_STOPAFTERBLOCKIMPORT{false};

/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB

extern std::atomic_bool fImporting;
extern std::atomic_bool fReindex;

typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;

struct CBlockIndexWorkComparator {
    bool operator()(const CBlockIndex* pa, const CBlockIndex* pb) const;
};

/**
 * Maintains a tree of blocks (stored in `m_block_index`) which is consulted
 * to determine where the most-work tip is.
 *
 * This data is used mostly in `CChainState` - information about, e.g.,
 * candidate tips is not maintained here.
 */
class BlockManager
{
    friend CChainState;
    friend ChainstateManager;

private:
    void FlushBlockFile(bool fFinalize = false, bool finalize_undo = false);
    void FlushUndoFile(int block_file, bool finalize = false);
    bool FindBlockPos(FlatFilePos& pos, unsigned int nAddSize, unsigned int nHeight, CChain& active_chain, uint64_t nTime, bool fKnown);
    bool FindUndoPos(BlockValidationState& state, int nFile, FlatFilePos& pos, unsigned int nAddSize);

    RecursiveMutex cs_LastBlockFile;
    std::vector<CBlockFileInfo> m_blockfile_info;
    int m_last_blockfile = 0;

    /** Dirty block file entries. */
    std::set<int> m_dirty_fileinfo;

public:
    BlockMap m_block_index GUARDED_BY(cs_main);

    /**
     * All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     */
    std::multimap<CBlockIndex*, CBlockIndex*> m_blocks_unlinked;
    std::unique_ptr<CBlockTreeDB> m_block_tree_db GUARDED_BY(::cs_main);

    /** Dirty block index entries. */
    std::set<CBlockIndex*> m_dirty_blockindex;

    bool WriteBlockIndexDB() EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool LoadBlockIndexDB(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /**
     * Load the blocktree off disk and into memory. Populate certain metadata
     * per index entry (nStatus, nChainWork, nTimeMax, etc.) as well as peripheral
     * collections like m_dirty_blockindex.
     */
    bool LoadBlockIndex(
        const Consensus::Params& consensus_params,
        ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Clear all data members. */
    void Unload() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex* AddToBlockIndex(const CBlockHeader& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Create a new block index entry for a given block hash */
    CBlockIndex* InsertBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex* LookupBlockIndex(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Get block file info entry for one block file */
    CBlockFileInfo* GetBlockFileInfo(size_t n);

    bool WriteUndoDataForBlock(const CBlockUndo& blockundo, BlockValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    FlatFilePos SaveBlockToDisk(const CBlock& block, int nHeight, CChain& active_chain, const CChainParams& chainparams, const FlatFilePos* dbp);

    /** Calculate the amount of disk space the block & undo files currently use */
    uint64_t CalculateCurrentUsage();

    //! Returns last CBlockIndex* that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const CCheckpointData& data) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    ~BlockManager()
    {
        Unload();
    }
};

/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const FlatFilePos& pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const FlatFilePos& pos);

/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock& block, const FlatFilePos& pos, const Consensus::Params& consensusParams);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);
bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const FlatFilePos& pos, const CMessageHeader::MessageStartChars& message_start);

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex);

void ThreadImport(ChainstateManager& chainman, std::vector<fs::path> vImportFiles, const ArgsManager& args);
} // namespace node

#endif // BITCOIN_NODE_BLOCKSTORAGE_H
