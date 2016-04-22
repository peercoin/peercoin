// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 The Peercoin developers
// Copyright (c) 2013-2014 The Peershares developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>
#include "net.h"
#include "util.h"

#define CHECKPOINT_MAX_SPAN (60 * 60 * 4) // max 4 hours before latest block

class uint256;
class CBlockIndex;
class CSyncCheckpoint;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);

    extern uint256 hashSyncCheckpoint;
    extern CSyncCheckpoint checkpointMessage;
    extern uint256 hashInvalidCheckpoint;
    extern CCriticalSection cs_hashSyncCheckpoint;

    CBlockIndex* GetLastSyncCheckpoint();
    bool WriteSyncCheckpoint(const uint256& hashCheckpoint);
    bool AcceptPendingSyncCheckpoint();
    uint256 AutoSelectSyncCheckpoint();
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev);
    bool WantedByPendingSyncCheckpoint(uint256 hashBlock);
    bool ResetSyncCheckpoint();
    void AskForPendingSyncCheckpoint(CNode* pfrom);
    bool SetCheckpointPrivKey(std::string strPrivKey);
    bool SendSyncCheckpoint(uint256 hashCheckpoint);
    bool IsMatureSyncCheckpoint();
    bool IsSyncCheckpointTooOld(unsigned int nSeconds);
}

// Peershares: synchronized checkpoint
class CUnsignedSyncCheckpoint
{
public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashCheckpoint);
    )

    void SetNull()
    {
        nVersion = 1;
        hashCheckpoint = 0;
    }

    std::string ToString() const
    {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                ")\n",
            nVersion,
            hashCheckpoint.ToString().c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
public:
    static const std::string strMasterPubKey;
    static std::string strMasterPrivKey;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
        READWRITE(vchSig);
    )

    void SetNull()
    {
        CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (hashCheckpoint == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool RelayTo(CNode* pnode) const
    {
        // returns true if wasn't already sent
        if (pnode->hashCheckpointKnown != hashCheckpoint)
        {
            pnode->hashCheckpointKnown = hashCheckpoint;
            pnode->PushMessage("checkpoint", *this);
            return true;
        }
        return false;
    }

    bool CheckSignature();
    bool ProcessSyncCheckpoint(CNode* pfrom);
};

#endif
