// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

#include <bignum.h>
#include <chainparams.h>
#include <kernel.h>
#include <atomic>

static std::atomic<const CBlockIndex *> cachedAnchor{nullptr};
static int64_t nDAAHalfLife = 24 * 60 * 60;

/**
 * ASERT caches a special block index for efficiency. If block indices are
 * freed then this needs to be called to ensure no dangling pointer when a new
 * block tree is created.
 * (this is temporary and will be removed after the ASERT constants are fixed)
 */

void ResetASERTAnchorBlockCache() noexcept {
    cachedAnchor = nullptr;
}

/**
 * Returns a pointer to the anchor block used for ASERT.
 * As anchor we use the last POW block for which IsProtocolV14() returns false.
 * This block happens to be the last block which was mined under the old
 * rules.
 *
 * This function is meant to be removed some time after the upgrade, once
 * the anchor block is deeply buried, and behind a hard-coded checkpoint.
 *
 * Preconditions: - pindex must not be nullptr
 *                - pindex must satisfy: IsProtocolV14(pindex) == true
 * Postcondition: Returns a pointer to the last (highest) POW block for which
 *                IsProtocolV14 is false.
 */
static const CBlockIndex *GetASERTAnchorBlock(const CBlockIndex *const pindex,
                                              const Consensus::Params &params) {
    assert(pindex);

    // - We check if we have a cached result, and if we do and it is really the
    //   ancestor of pindex, then we return it.
    //
    // - If we do not or if the cached result is not the ancestor of pindex,
    //   then we proceed with the more expensive walk back to find the ASERT
    //   anchor block.
    //
    // CBlockIndex::GetAncestor() is reasonably efficient; it uses
    // CBlockIndex::pskip Note that if pindex == cachedAnchor, GetAncestor()
    // here will return cachedAnchor, which is what we want.
    const CBlockIndex *lastCached = cachedAnchor.load();
    if (lastCached && pindex->GetAncestor(lastCached->nHeight) == lastCached) {
        return lastCached;
    }

    // Slow path: walk back until we find the first PoW block for which
    // IsProtocolV14 == false.
    const CBlockIndex *anchor = pindex;

    while (anchor->pprev) {
        // first, skip backwards testing IsProtocolV14
        // The below code leverages CBlockIndex::pskip to walk back efficiently.
        if (anchor->pskip && IsProtocolV14(anchor->pskip)) {
            // skip backward
            anchor = anchor->pskip;
            // continue skipping
            continue;
        }
        // cannot skip here, walk back by 1
        if (!IsProtocolV14(anchor->pprev) && anchor->IsProofOfWork()) {
            // found it -- highest block where ASERT is not enabled is
            // anchor->pprev, and anchor points to the last POW block for which
            // IsProtocolV14() == false
            break;
        }
        anchor = anchor->pprev;
    }

    // Overwrite the cache with the anchor we found. More likely than not, the
    // next time we are asked to validate a header it will be part of same /
    // similar chain, not some other unrelated chain with a totally different
    // anchor.
    cachedAnchor = anchor;

    return anchor;
}

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockIndex *pindex,
                                  const Consensus::Params &params) noexcept {
    return GetNextASERTWorkRequired(pindexPrev, pindex, params,
                                    GetASERTAnchorBlock(pindexPrev, params));
}

/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block
 * every 600 seconds), and we calculate the difficulty based on how far the most
 * recent block's timestamp is ahead of or behind that schedule. We set our
 * targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or
 * behind schedule we get, we double or halve the difficulty.
 */
uint32_t
GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                         const CBlockIndex *pindex,
                         const Consensus::Params &params,
                         const CBlockIndex *pindexAnchorBlock) noexcept {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // Anchor block is the block on which all ASERT scheduling calculations are
    // based. It too must exist, and it must have a valid parent.
    assert(pindexAnchorBlock != nullptr);

    // We make no further assumptions other than the height of the prev block
    // must be >= that of the anchor block.
    assert(pindexPrev->nHeight >= pindexAnchorBlock->nHeight);

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // For nTimeDiff calculation, the timestamp of the parent to the anchor
    // block is used, as per the absolute formulation of ASERT. This is somewhat
    // counterintuitive since it is referred to as the anchor timestamp, but as
    // per the formula the timestamp of block M-1 must be used if the anchor is
    // M.
    assert(pindexPrev->pprev != nullptr);
    // Note: time difference is to parent of anchor block (or to anchor block
    // itself iff anchor is genesis).
    //       (according to absolute formulation of ASERT)
    const auto anchorTime = pindexAnchorBlock->pprev
                                ? pindexAnchorBlock->pprev->GetBlockTime()
                                : pindexAnchorBlock->GetBlockTime();
    const int64_t nTimeDiff = pindex->GetBlockTime() - anchorTime;
    // Height difference is from current block to anchor block
    const int64_t nHeightDiff =
        pindexPrev->nHeight - pindexAnchorBlock->nHeight -
        (pindexPrev->nHeightStake - pindexAnchorBlock->nHeightStake);
    const arith_uint256 refBlockTarget =
        arith_uint256().SetCompact(pindexAnchorBlock->nBits);
    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    arith_uint256 nextTarget =
        CalculateASERT(refBlockTarget, params.nStakeTargetSpacing * 6, nTimeDiff,
                       nHeightDiff, powLimit, nDAAHalfLife);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff, const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {
    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0 && refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to
    // handle overflows easily. 28 leading zero bits should be enough.
    assert((powLimit >> 228) == 0);

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using
    // only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME *
    //     (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) <
           (1ll << (63 - 16)));
    const int64_t exponent =
        ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) /
        nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into
    // the [0, 1) interval. The truncated exponent tells us how many shifts we
    // need to do Note1: This needs to be a right shift. Right shift rounds
    // downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated
    //        division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x <
    // 1 Error versus actual 2^x is less than 0.013%.
    const uint32_t factor =
        65536 + ((+195766423245049ull * frac + 971821376ull * frac * frac +
                  5127ull * frac * frac * frac + (1ull << 47)) >>
                 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            nextTarget = powLimit;
        } else {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    // we return from only 1 place for copy elision
    return nextTarget;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params)
{
    if (pindexLast == nullptr || params.fPowNoRetargeting)
        return UintToArith256(params.powLimit).GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return UintToArith256(params.bnInitialHashTarget).GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == nullptr)
        return UintToArith256(params.bnInitialHashTarget).GetCompact(); // second block

    if (!fProofOfStake && IsProtocolV14(pindexPrev))
        return GetNextASERTWorkRequired(pindexPrev, pindexLast, params);

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // rfc20
    int64_t nHypotheticalSpacing = pindexLast->GetBlockTime() - pindexPrev->GetBlockTime();
    if (!fProofOfStake && IsProtocolV12(pindexPrev) && (nHypotheticalSpacing > nActualSpacing))
        nActualSpacing = nHypotheticalSpacing;

    // peercoin: target change every block
    // peercoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST) {
        int64_t nTargetSpacing;

        if (fProofOfStake) {
            nTargetSpacing = params.nStakeTargetSpacing;
        } else {
            if (IsProtocolV09(pindexLast->nTime)) {
                nTargetSpacing = params.nStakeTargetSpacing * 6;
            } else {
                nTargetSpacing = std::min(params.nTargetSpacingWorkMax, params.nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
            }
        }

        int64_t nInterval = params.nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);
        }

    if (bnNew > CBigNum(params.powLimit))
        bnNew = CBigNum(params.powLimit);

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
