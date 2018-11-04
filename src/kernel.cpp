// Copyright (c) 2012-2019 The Peercoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <bignum.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <kernel.h>
#include <random.h>
#include <streams.h>
#include <timedata.h>
#include <txdb.h>
#include <util.h>
#include <validation.h>

namespace Kernel
{

using Consensus::Params;

// Factored out to avoid repetition.
struct DebugFlags {
    bool fDebug;
    bool fPrintStakeModifier;

    DebugFlags()
    {
        fDebug = gArgs.GetBoolArg("-debug", false) || gArgs.GetBoolArg("-kerneldebug", false);
        fPrintStakeModifier = gArgs.GetBoolArg("-printstakemodifier", false);
    }
};

// protocols

// Rationale:
// * Protocol version detection can be factored out.
// * Version-dependent branches use comparison operators.
// * Switch times can be neatly organized into a 2D table.

enum struct Protocol : size_t {
    V02, V03, V04, V05, V06, V07,
    Invalid // keep last
};

constexpr auto nProtocols = static_cast<size_t>(Protocol::Invalid);

constexpr bool operator<(Protocol p1, Protocol p2)
{
    return static_cast<size_t>(p1) < static_cast<size_t>(p2);
}

constexpr bool operator>=(Protocol p1, Protocol p2)
{
    return static_cast<size_t>(p1) >= static_cast<size_t>(p2);
}

static const std::array<char const*, nProtocols> ProtocolNames{{
    "v0.2", "v0.3", "v0.4", "v0.5", "v0.6", "v0.7"
}};

constexpr char const* ProtocolName(Protocol p)
{
    return p < Protocol::Invalid ? ProtocolNames[static_cast<size_t>(p)] : "v???";
}

// networks

enum struct Network : size_t {
    Main,
    Test,
    Invalid // keep last
};

constexpr auto nNetworks = static_cast<size_t>(Network::Invalid);

using ExtPubKey = std::array<unsigned char, 4>;

static const std::array<ExtPubKey, nNetworks> ExtPubKeys{{
    {0x04, 0x88, 0xB2, 0x1E}, // Main
    {0x04, 0x35, 0x83, 0x9F}  // Test
}};

Network DetectNetwork(const CChainParams& params)
{
    auto epkIt = params.Base58Prefix(CChainParams::EXT_PUBLIC_KEY).begin();
    for (size_t k = 0u; k < nNetworks; ++k) {
        auto& epk = ExtPubKeys[k];
        if (std::equal(epk.begin(), epk.end(), epkIt))
            return static_cast<Network>(k);
    }
    return Network::Invalid;
}

// protocol switch times

static constexpr std::array<std::array<uint32_t, nNetworks>, nProtocols> SwitchTimes{{
    {0, 0},                   // V02
    {1363800000, 1359781000}, // V03
    {1399300000, 1395700000}, // V04
    {1461700000, 1447700000}, // V05
    {1513050000, 1508198400}, // V06
    {1552392000, 1541505600}, // V07
}};

constexpr uint32_t GetSwitchTime(Network network, Protocol protocol)
{
    return SwitchTimes[static_cast<size_t>(protocol)][static_cast<size_t>(network)];
}

// Switch time for new BIPs from bitcoin 0.16.x
const uint32_t nBTC16BIPsSwitchTime = 1559260800; // Fri 31 May 00:00:00 UTC 2019

// checkpoints

// Hard checkpoints of stake modifiers to ensure they are deterministic.

struct Checkpoint {
    int nHeight;
    uint32_t nChecksum;
};

static constexpr Checkpoint checkpointsMain[] = {
    {       0, 0x0e00670bu },
    {   19080, 0xad4e4d29u },
    {   30583, 0xdc7bf136u },
    {   99999, 0xf555cfd2u },
    {  219999, 0x91b7444du },
    {  336000, 0x6c3c8048u },
    {  371850, 0x9b850bdfu },
    {  407813, 0x46fe50b5u },
    {-1, 0} // Sentinel
};

static constexpr Checkpoint checkpointsTest[] = {
    {       0, 0x0e00670bu },
    {   19080, 0x3711dc3au },
    {   30583, 0xb480fadeu },
    {   99999, 0x9a62eaecu },
    {  219999, 0xeafe96c3u },
    {  336000, 0x8330dc09u },
    {  372751, 0xafb94e2fu },
    {  382019, 0x7f5cf5ebu },
    {-1, 0} // Sentinel
};

static constexpr std::array<Checkpoint const*, nNetworks> checkpoints{{
    checkpointsMain, checkpointsTest
}};

bool CheckStakeModifierChecksum(Network network, int nHeight, uint32_t nChecksum)
{
    Checkpoint const* pCheckpoint = checkpoints[static_cast<size_t>(network)];
    while (pCheckpoint->nHeight != -1 && pCheckpoint->nHeight < nHeight) ++pCheckpoint;
    return pCheckpoint->nHeight != nHeight || pCheckpoint->nChecksum == nChecksum;
}

// selection params

// The selection interval is partitioned into 64 sections, whose durations
// depend on the modifier interval. This structure computes all the section
// durations and their sum, and caches the results.

struct SelectionParams {
    int64_t nInterval;
    int64_t nIntervalSections[64];

    SelectionParams(const Params&);
};

SelectionParams::SelectionParams(const Params& params)
{
    nInterval = 0;
    for (int64_t i = 0; i < 64; ++i) {
        auto nDiv = 63 + (63 - i) * (MODIFIER_INTERVAL_RATIO - 1);
        auto nSection = params.nModifierInterval * 63 / nDiv;
        nIntervalSections[i] = nSection;
        nInterval += nSection;
    }
}

// selection

// Candidate blocks are selected based on their block time and selection hash.
// This structure caches the computed selection hash, and provides the required
// lexicographic ordering by (block time, block hash).
struct SelectionBlock {
    const CBlockIndex* pindex;
    arith_uint256 hashSelection;

    // The selection hash depends on the previous stake modifier.
    // Note that the stake modifier is the same for all candidates.
    SelectionBlock(const CBlockIndex* pindex, uint64_t stakeModifier)
        : pindex{pindex}
    {
        bool fPOS = pindex->IsProofOfStake();

        // The other input varies with each candidate block.
        uint256 hashProof = fPOS ? pindex->hashProofOfStake : pindex->GetBlockHash();

        CDataStream ss{SER_GETHASH, 0};
        ss << hashProof << stakeModifier;
        hashSelection = UintToArith256(Hash(ss.begin(), ss.end()));

        // In order to preserve the energy efficiency property, selection favors
        // proof-of-stake candidates over proof-of-work ones. The selected
        // candidate in each round is the one with the smallest selection hash,
        // which will almost always be a proof-of-stake block if there are any.
        if (fPOS) hashSelection >>= 32u;
    }

    int64_t GetTime() const {
        return pindex->GetBlockTime();
    }

    bool operator<(const SelectionBlock& x) const
    {
        auto t1 = GetTime(), t2 = x.GetTime();
        return t1 != t2 ? t1 < t2 : pindex->GetBlockHash() < x.pindex->GetBlockHash();
    }
};

struct Selection {
    const Params& params;
    const SelectionParams& selParams;

    std::vector<SelectionBlock> vBlocks;
    int64_t nTimeStart;
    int64_t nTimeStop;

    Selection(const Params& params, const SelectionParams& selParams)
        : params{params}, selParams{selParams}
    {
        vBlocks.reserve(64 * params.nModifierInterval / params.nStakeTargetSpacing);
        nTimeStart = nTimeStop = 0;
    }


    void Collect(const CBlockIndex* pindex, uint64_t stakeModifier);
    void Select();
    uint64_t ComputeModifier() const;

    void Log() const;
};

template <typename T>
T RoundDown(T nValue, T nDivisor)
{
    return (nValue / nDivisor) * nDivisor;
}

// Given the previous block and previous stake modifier, collect all the
// candidate blocks for the next stake modifier, compute their selection hashes
// and sort them in the required order for Select().
void Selection::Collect(const CBlockIndex* pindex, uint64_t stakeModifier)
{
    nTimeStart = RoundDown(pindex->GetBlockTime(), params.nModifierInterval) - selParams.nInterval;

    // The candidates are the longest contiguous sequence of blocks up to and
    // including the previous block (pindex) such that no block time is earlier
    // than the selection interval.
    vBlocks.clear();
    while (pindex && pindex->GetBlockTime() >= nTimeStart) {
        vBlocks.push_back(SelectionBlock{pindex, stakeModifier});
        pindex = pindex->pprev;
    }

    // Reversal orders the candidates by increasing height, approximating
    // the correct order.
    std::reverse(vBlocks.begin(), vBlocks.end());
    std::sort(vBlocks.begin(), vBlocks.end());
}

// After the candidates have been collected, select at most 64 round winners,
// and discard the rest. The selected blocks are left in round order.
void Selection::Select()
{
    nTimeStop = nTimeStart;

    size_t nLimit = std::min<size_t>(64u, vBlocks.size());
    for (size_t nRound = 0u, nRemaining = nLimit; nRemaining; --nRemaining, ++nRound) {
        // Extend the selection interval for this round with the corresponding section.
        nTimeStop += selParams.nIntervalSections[nRound];

        // The remaining candidates start at index nRound and continue to the end
        // of vBlocks with nondecreasing block times.
        // If there is only one candidate, it wins by default.
        // If there are more, the winner is the first candidate with the least
        // selection hash among those contained in the selection interval.
        size_t nSelected = 0u;
        for (auto nCandidate = 1u; nRound + nCandidate < vBlocks.size(); ++nCandidate) {
            auto& block = vBlocks[nRound + nCandidate];
            if (block.GetTime() > nTimeStop) break;

            if (block.hashSelection < vBlocks[nRound + nSelected].hashSelection)
                nSelected = nCandidate;
        }

        // Move the winner to the round slot, keeping the remaining candidates sorted.
        auto itBegin = vBlocks.begin() + nRound;
        std::rotate(itBegin, itBegin + nSelected, itBegin + nSelected + 1);
    }

    // Discard losing candidates.
    vBlocks.erase(vBlocks.begin() + nLimit, vBlocks.end());
}

// Collect the entropy bits of selected blocks into the new stake modifier.
uint64_t Selection::ComputeModifier() const
{
    uint64_t nStakeModifier = 0;
    for (auto it = vBlocks.rbegin(); it != vBlocks.rend(); ++it) {
        nStakeModifier <<= 1;
        nStakeModifier |= it->pindex->GetStakeEntropyBit();
    }
    return nStakeModifier;
}

void Selection::Log() const
{
    size_t nRound = 0;
    size_t nStop = nTimeStart;
    for (auto& block : vBlocks) {
        nStop += selParams.nIntervalSections[nRound];
        LogPrintf("stake modifier selection: round=%u stop=%s height=%u hash=%s\n", nRound, DateTimeStrFormat(nStop), block.pindex->nHeight, block.hashSelection.ToString());
        ++nRound;
    }
}

// stake modifiers

// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.

struct StakeModifier {
    uint64_t nModifier = 0;
    int64_t nTime = 0;
    int32_t nHeight = 0;

    StakeModifier() = default;

    StakeModifier(const CBlockIndex& pindex)
        : nModifier{pindex.nStakeModifier}
        , nTime{pindex.GetBlockTime()}
        , nHeight{pindex.nHeight}
    {}

    void Log() const;
};

void StakeModifier::Log() const
{
    LogPrintf("stake modifier=%016x at height=%d time=%s epoch=%d\n", nModifier, nHeight, DateTimeStrFormat(nTime), nTime);
}

const CBlockIndex* FindLastStakeModifierBlock(const CBlockIndex* pindex)
{
    while (pindex && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    return pindex;
}

// validation

// Kernel hash is computed based on these values, rationale for each is given
// below.
// Block and transaction hashes should not be used here, as they can be
// generated in vast quantities, which would degrade the system into
// proof-of-work.
struct HashInputs {
    Protocol protocol = Protocol::Invalid;
    unsigned int nBits;

    // The stake modifier.
    // (v0.2)   nBits is used, which depends on all past block timestamps.
    // (v0.3)   Static stake modifier, around 9 days after the staked coin.
    // (v0.5)   Dynamic stake modifier, around 21 days before the kernel.
    uint64_t nStakeModifier;

    // Block timestamp of the staked coin. Prevents nodes from guessing a good
    // timestamp to generate transaction for future advantage.
    unsigned int nTimeBlockFrom;

    // Offset of staked coin transaction within block, its timestamp and output
    // number. All of these reduce the chance of nodes generating coinstake at
    // the same time.
    unsigned int nTxPrevOffset;
    unsigned int nTimeTxPrev;
    unsigned int nPrevOutput;

    // Kernel timestamp.
    unsigned int nTimeTx;

    //
    uint256 ComputeHash() const;
    void Log() const;
};

uint256 HashInputs::ComputeHash() const
{
    CDataStream ss{SER_GETHASH, 0};

    if (protocol == Protocol::V02)
        ss << nBits; // 4 bytes
    else
        ss << nStakeModifier; // 8 bytes

    ss << nTimeBlockFrom << nTxPrevOffset << nTimeTxPrev << nPrevOutput << nTimeTx;

    return Hash(ss.begin(), ss.end());
}

void HashInputs::Log() const
{
    LogPrintf("modifier=%#018x nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u",
            nStakeModifier, nTimeBlockFrom, nTxPrevOffset, nTimeTxPrev, nPrevOutput, nTimeTx);
}

// This structure contains everything needed to validate coinstake transactions.
struct CoinStake : public HashInputs {
    int64_t nValueIn;
    uint256 hashBlockFrom;
    const CBlockIndex* pindexPrev;

    void Log() const;

    bool Check(const Params&, uint256& hashProofOfStake) const;

    bool Load(const CTransactionRef& tx);

    void DetectProtocol(Network network);
};

void CoinStake::Log() const
{
    LogPrintf("protocol=%s ", ProtocolName(protocol));
    HashInputs::Log();
    LogPrintf(" nValueIn=%d", nValueIn);
}

// Check that the coinstake transaction satisfies the kernel protocol.
bool CoinStake::Check(const Params& params, uint256& hashProofOfStake) const
{
    static char const* function = "Kernel::CoinStake::Check";

    // Sanity checks.
    if (nTimeTx < nTimeTxPrev)
        return error("%s(): transaction time violation.", function);
    if (nTimeBlockFrom + params.nStakeMinAge > nTimeTx)
        return error("%s(): minimal stake age violation.", function);

    // Compute the kernel hash.
    hashProofOfStake = ComputeHash();

    // The target is proportional to stake age, which is limited to 90 days.
    auto nTimeWeight = std::min<int64_t>(nTimeTx - nTimeTxPrev, params.nStakeMaxAge);
    if (protocol >= Protocol::V03) {
        // Starting with v0.3, coins start accumulating (positive) coin age
        // with a 30-day delay. This increases the number of active coins
        // participating in the hash and helps secure the network when
        // proof-of-stake difficulty is low.
        nTimeWeight -= params.nStakeMinAge;
    }

    // The target is proportional to stake value.
    auto bnCoinDayWeight = CBigNum(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);

    // The target depends on the current difficulty, encoded in nBits.
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    // The kernel hash must meet target.
    if (CBigNum(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay)
        return error("%s(): proof-of-stake hash does not meet target.", function);

    return true;
}

bool LoadTx(const uint256& hashTx,
    CTransactionRef& tx,
    CBlockHeader& header,
    unsigned int& nTxOffset)
{
    static char const* function = "Kernel::LoadTx";

    if (!fTxIndex)
        return error("%s(): transaction index not available", function);

    CDiskTxPos posTx;
    if (!pblocktree->ReadTxIndex(hashTx, posTx))
        return error("%s(%s): transaction index not found", function, hashTx.ToString());

    CAutoFile file(OpenBlockFile(posTx, true), SER_DISK, CLIENT_VERSION);
    try {
        file >> header;
        fseek(file.Get(), posTx.nTxOffset, SEEK_CUR);
        file >> tx;
    } catch (...) {
        return error("%s(%s) : deserialize or I/O error", function, hashTx.ToString());
    }

    if (tx->GetHash() != hashTx)
        return error("%s(%s) : txid mismatch", function, hashTx.ToString());

    nTxOffset = posTx.nTxOffset + CBlockHeader::NORMAL_SERIALIZE_SIZE;

    return true;
}

// Load hash inputs and other data relevant for validation from the given
// coinstake transaction and the block/transaction containing the staked coin.
bool CoinStake::Load(const CTransactionRef& tx)
{
    static char const* function = "Kernel::Coinstake::Load";

    auto txid = tx->GetHash().ToString();

    if (!tx->IsCoinStake())
        return error("%s(%s): not a coinstake transaction.", function, txid);

    const CTxIn& kernel = tx->vin[0];

    nTimeTx = tx->nTime;
    nPrevOutput = kernel.prevout.n;

    CBlockHeader blockFrom;
    CTransactionRef txPrev;
    if (!LoadTx(kernel.prevout.hash, txPrev, blockFrom, nTxPrevOffset))
        return error("%s(%s): could not load staked coin.", function, txid);

    hashBlockFrom = blockFrom.GetHash();
    nTimeBlockFrom = blockFrom.GetBlockTime();
    nTimeTxPrev = txPrev->nTime;
    nValueIn = txPrev->vout[nPrevOutput].nValue;

    return true;
}

void CoinStake::DetectProtocol(Network network)
{
    if (nTimeTx >= GetSwitchTime(network, Protocol::V05))
        protocol = Protocol::V05;
    else if (nTimeTx >= GetSwitchTime(network, Protocol::V03))
        protocol = Protocol::V03;
    else
        protocol = Protocol::V02;
}

// state

class State : public DebugFlags
{
public:
    const Params& params;
    const SelectionParams selParams;
    const Network network;

    State(const CChainParams& chainParams)
        : DebugFlags{}
        , params{chainParams.GetConsensus()}
        , selParams{params}
        , network{DetectNetwork(chainParams)}
    {
    }

    bool CheckCoinStake(CoinStake&, uint256& hashProofOfStake, bool* pfDoS = nullptr) const;

    bool ComputeNextStakeModifier(const CBlockIndex*, uint64_t& nStakeModifier, bool& fGenerated) const;

private:
    bool GetStakeModifierV03(const CoinStake&, StakeModifier& out) const;
    bool GetStakeModifierV05(const CoinStake&, StakeModifier& out) const;
};

// This is the common part of CheckProofOfStake and CheckStakeKernelHash.
// All CoinStake members except protocol and nStakeModifier are assumed to be
// initialized.
bool State::CheckCoinStake(CoinStake& coinStake, uint256& hashProofOfStake, bool* pfDoS) const
{
    static char const* function = "Kernel::State::CheckCoinStake";

    coinStake.DetectProtocol(network);

    // Choose the stake modifier based on protocol version.
    if (coinStake.protocol >= Protocol::V03) {
        StakeModifier stakeMod;

        if (coinStake.protocol >= Protocol::V05) {
            if (!GetStakeModifierV05(coinStake, stakeMod)) return false;
        } else {
            if (!GetStakeModifierV03(coinStake, stakeMod)) return false;
        }

        if (fDebug) stakeMod.Log();
        coinStake.nStakeModifier = stakeMod.nModifier;
    } else {
        coinStake.nStakeModifier = coinStake.nBits;
    }

    bool okay = coinStake.Check(params, hashProofOfStake);
    if (pfDoS) *pfDoS = !okay;

    if (fDebug || !okay) {
        LogPrintf("%s(): ", function);
        coinStake.Log();
        LogPrintf(" hashProof=%s\n", hashProofOfStake.ToString());
    }

    if (!okay)
        return error("%s(): kernel check failed.", function);

    return true;
}

/*
bool State::CheckProofOfStake(CValidationState& state, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake) const
{
    static char const* function = "Kernel::State::CheckProofOfStake";

    CoinStake coinStake;
    coinStake.nBits = nBits;

    if (!coinStake.Load(tx))
        return error("%s(): could not load coin stake tx.", function);

    bool fDoS = false;
    if (!CheckCoinStake(coinStake, hashProofOfStake, &fDoS))
        return fDoS && state.DoS(1);

    return true;
}
*/

// V0.3: Stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
bool State::GetStakeModifierV03(const CoinStake& coinStake, StakeModifier& out) const
{
    auto it = mapBlockIndex.find(coinStake.hashBlockFrom);
    if (it == mapBlockIndex.end())
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindexFrom = it->second;

    auto nMinTime = pindexFrom->GetBlockTime() + selParams.nInterval;
    auto nMinHeight = pindexFrom->nHeight;
    auto nMaxHeight = coinStake.pindexPrev->nHeight;

    const CBlockIndex* pindexBest = nullptr;

    // Iterate backwards from previous block while off active chain.
    for (auto it = coinStake.pindexPrev;
            it->nHeight >= nMinHeight && !chainActive.Contains(it);
            it = it->pprev)
    {
        if (it->GeneratedStakeModifier() && it->GetBlockTime() >= nMinTime) pindexBest = it;
        nMaxHeight = it->nHeight - 1;
    }

    // Iterate forwards while on active chain.
    for (auto it = pindexFrom;
            it && it->nHeight <= nMaxHeight;
            it = chainActive.Next(it))
    {
        if (it->GeneratedStakeModifier() && it->GetBlockTime() >= nMinTime)
        {
            pindexBest = it;
            break;
        }
    }

    if (pindexBest)
    {
        out.nModifier = pindexBest->nStakeModifier;
        out.nHeight = pindexBest->nHeight;
        out.nTime = pindexBest->GetBlockTime();
    }

    return !!pindexBest;
}

// V0.5: Stake modifier used to hash for a stake kernel is chosen as the stake
// modifier that is (nStakeMinAge minus a selection interval) earlier than the
// stake, thus at least a selection interval later than the coin generating the
// kernel, as the generating coin is from at least nStakeMinAge ago.
bool State::GetStakeModifierV05(const CoinStake& coinStake, StakeModifier& out) const
{
    const CBlockIndex* pindex = coinStake.pindexPrev;
    out.nHeight = pindex->nHeight;
    out.nTime = pindex->GetBlockTime();

    if (out.nTime + params.nStakeMinAge - selParams.nInterval <= coinStake.nTimeTx)
        return error("GetKernelStakeModifier() : best block %s at height %d too old for stake",
            pindex->GetBlockHash().ToString(), pindex->nHeight);

    while (out.nTime + params.nStakeMinAge - selParams.nInterval > coinStake.nTimeTx) {
        if (!pindex->pprev)
            return error("GetKernelStakeModifier() : reached genesis block");
        pindex = pindex->pprev;
        if (pindex->GeneratedStakeModifier()) {
            out.nHeight = pindex->nHeight;
            out.nTime = pindex->GetBlockTime();
        }
    }

    out.nModifier = pindex->nStakeModifier;
    return true;
}

bool State::ComputeNextStakeModifier(const CBlockIndex* pindexCurrent,
    uint64_t& nStakeModifier,
    bool& fGenerated) const
{
    static char const* function = "ComputeNextStakeModifier";

    const CBlockIndex* pindexPrev = pindexCurrent->pprev;

    nStakeModifier = 0;
    fGenerated = false;
    if (!pindexPrev) {
        fGenerated = true;
        return true; // genesis block's modifier is 0
    }

    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    auto pindexLastMod = Kernel::FindLastStakeModifierBlock(pindexPrev);
    if (!pindexLastMod)
        return error("%s(): cannot find last stake modifier", function);

    Kernel::StakeModifier lastMod{*pindexLastMod};
    nStakeModifier = lastMod.nModifier;

    if (fDebug)
        LogPrintf("%s(): previous modifier=%#016x time=%s epoch=%d\n", function, nStakeModifier, DateTimeStrFormat(lastMod.nTime), lastMod.nTime);

    auto nModIdx = lastMod.nTime / params.nModifierInterval;

    if (nModIdx >= pindexPrev->GetBlockTime() / params.nModifierInterval) {
        if (fDebug)
            LogPrintf("%s(): no new interval keep current modifier: pindexPrev nHeight=%d nTime=%u\n", function, pindexPrev->nHeight, (unsigned int)pindexPrev->GetBlockTime());
        return true;
    }

    if (nModIdx >= pindexCurrent->GetBlockTime() / params.nModifierInterval) {
        // v0.4+ requires current block timestamp also be in a different modifier interval
        if (pindexCurrent->nTime >= Kernel::GetSwitchTime(network, Kernel::Protocol::V04)) {
            if (fDebug)
                LogPrintf("%s(v0.4+): no new interval keep current modifier: pindexCurrent nHeight=%d nTime=%u\n", function, pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
            return true;
        } else {
            if (fDebug)
                LogPrintf("%s(): v0.3 modifier at block %s not meeting v0.4+ protocol: pindexCurrent nHeight=%d nTime=%u\n", function, pindexCurrent->GetBlockHash().ToString(), pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
        }
    }

    // Compute the next stake modifier from selected preceding blocks.
    Selection sel{params, selParams};
    sel.Collect(pindexPrev, lastMod.nModifier);
    sel.Select();

    nStakeModifier = sel.ComputeModifier();
    fGenerated = true;

    if (fDebug) {
        if (fPrintStakeModifier) sel.Log();
        LogPrintf("%s(): new stake modifier=%#016x\n", function, nStakeModifier);
    }

    return true;
}

} // namespace Kernel

// Whether the given coinstake is subject to new v0.3 protocol
bool IsProtocolV03(unsigned int nTimeCoinStake)
{
    auto network = Kernel::DetectNetwork(Params());
    return nTimeCoinStake >= Kernel::GetSwitchTime(network, Kernel::Protocol::V03);
}

// Whether the given block is subject to new v0.4 protocol
bool IsProtocolV04(unsigned int nTimeBlock)
{
    auto network = Kernel::DetectNetwork(Params());
    return nTimeBlock >= Kernel::GetSwitchTime(network, Kernel::Protocol::V04);
}

// Whether the given transaction is subject to new v0.5 protocol
bool IsProtocolV05(unsigned int nTimeTx)
{
    auto network = Kernel::DetectNetwork(Params());
    return nTimeTx >= Kernel::GetSwitchTime(network, Kernel::Protocol::V05);
}

// Whether a given block is subject to new v0.6 protocol
// Test against previous block index! (always available)
bool IsProtocolV06(const CBlockIndex* pindexPrev)
{
    auto network = Kernel::DetectNetwork(Params());
    if (pindexPrev->nTime < Kernel::GetSwitchTime(network, Kernel::Protocol::V06))
        return false;

    // if 900 of the last 1,000 blocks are version 2 or greater (90/100 if testnet):
    // Soft-forking PoS can be dangerous if the super majority is too low
    // The stake majority will decrease after the fork
    // since only coindays of updated nodes will get destroyed.
    switch (network) {
    case Kernel::Network::Main:
        return IsSuperMajority(2, pindexPrev, 900, 1000);

    case Kernel::Network::Test:
        return IsSuperMajority(2, pindexPrev, 90, 100);

    default:
        return false;
    }
}

// Whether a given transaction is subject to new v0.7 protocol
bool IsProtocolV07(unsigned int nTimeTx)
{
    auto network = Kernel::DetectNetwork(Params());
    return nTimeTx >= GetSwitchTime(network, Kernel::Protocol::V07);
}

bool IsBTC16BIPsEnabled(uint32_t nTimeTx)
{
    return nTimeTx >= Kernel::nBTC16BIPsSwitchTime;
}

bool ComputeNextStakeModifier(const CBlockIndex* pindexCurrent, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    Kernel::State kernel{Params()};
    return kernel.ComputeNextStakeModifier(pindexCurrent, nStakeModifier, fGeneratedStakeModifier);
}

bool CheckStakeKernelHash(unsigned int nBits, const CBlockIndex* pindexPrev, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTransactionRef& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake)
{
    Kernel::State kernel{Params()};

    Kernel::CoinStake x;
    x.nBits = nBits;
    x.pindexPrev = pindexPrev;
    x.hashBlockFrom = blockFrom.GetHash();
    x.nTimeBlockFrom = blockFrom.GetBlockTime();
    x.nTxPrevOffset = nTxPrevOffset;
    x.nTimeTxPrev = txPrev->nTime;
    x.nPrevOutput = prevout.n;
    x.nValueIn = txPrev->vout[prevout.n].nValue;
    x.nTimeTx = nTimeTx;

    return kernel.CheckCoinStake(x, hashProofOfStake);
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(CValidationState& state, const CBlockIndex* pindexPrev, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake)
{
    Kernel::State kernel{Params()};

    Kernel::CoinStake coinStake;
    coinStake.nBits = nBits;
    coinStake.pindexPrev = pindexPrev;

    if (!coinStake.Load(tx))
        return error("CheckProofOfStake(): could not load coin stake tx.");

    bool fDoS = false;
    if (!kernel.CheckCoinStake(coinStake, hashProofOfStake, &fDoS))
        return fDoS && state.DoS(1);

    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    auto network = Kernel::DetectNetwork(Params());
    if (nTimeTx >= Kernel::GetSwitchTime(network, Kernel::Protocol::V03)) // v0.3 protocol
        return (nTimeBlock == nTimeTx);
    else // v0.2 protocol
        return ((nTimeTx <= nTimeBlock) && (nTimeBlock <= nTimeTx + MAX_FUTURE_BLOCK_TIME));
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->GetBlockHash() == Params().GetConsensus().hashGenesisBlock);
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    arith_uint256 hashChecksum = UintToArith256(Hash(ss.begin(), ss.end()));
    hashChecksum >>= (256 - 32);
    return hashChecksum.GetLow64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    auto network = Kernel::DetectNetwork(Params());
    return Kernel::CheckStakeModifierChecksum(network, nHeight, nStakeModifierChecksum);
}

bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; pstart = pstart->pprev) {
        if (!pstart->IsProofOfStake())
            continue;

        if (pstart->nVersion >= minVersion)
            ++nFound;

        i++;
    }
    return (nFound >= nRequired);
}

// peercoin: entropy bit for stake modifier if chosen by modifier
unsigned int GetStakeEntropyBit(const CBlock& block)
{
    Kernel::DebugFlags flags;
    auto network = Kernel::DetectNetwork(Params());
    bool fV04 = block.nTime >= Kernel::GetSwitchTime(network, Kernel::Protocol::V04);

    unsigned int nEntropyBit = 0;
    std::string logHash;

    if (fV04) {
        auto hashBlock = block.GetHash();
        nEntropyBit = UintToArith256(hashBlock).GetLow64() & 1llu; // last bit of block hash

        if (flags.fPrintStakeModifier) {
            logHash = "Block=";
            logHash += hashBlock.ToString();
        }
    } else {
        // old protocol for entropy bit pre v0.4
        uint160 hashSig = Hash160(block.vchBlockSig);
        nEntropyBit = hashSig.GetDataPtr()[4] >> 31; // take the first bit of the hash

        if (flags.fPrintStakeModifier) {
            logHash = "Sig=";
            logHash += hashSig.ToString();
        }
    }

    if (flags.fPrintStakeModifier)
        LogPrintf("GetStakeEntropyBit(%s): nTime=%d, hash%s, entropyBit=%d\n",
            fV04 ? "v0.4+" : "v0.3", block.nTime, logHash, nEntropyBit);

    return nEntropyBit;
}

