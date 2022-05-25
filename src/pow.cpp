// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
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

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params)
{
    if (pindexLast == nullptr)
        return UintToArith256(params.powLimit).GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return UintToArith256(params.bnInitialHashTarget).GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == nullptr)
        return UintToArith256(params.bnInitialHashTarget).GetCompact(); // second block

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

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
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
