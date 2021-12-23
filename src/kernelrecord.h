// Copyright (c) 2012-2022 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PEERCOIN_KERNELRECORD_H
#define PEERCOIN_KERNELRECORD_H

#include <uint256.h>
#include <interfaces/wallet.h>

class CWallet;
class CWalletTx;

class KernelRecord
{
public:
    KernelRecord():
        hash(), nTime(0), address(""), nValue(0), idx(0), spent(false), prevMinutes(0), prevDifficulty(0), prevProbability(0)
    {
    }

    KernelRecord(uint256 hash, int64_t nTime):
            hash(hash), nTime(nTime), address(""), nValue(0), idx(0), spent(false), prevMinutes(0), prevDifficulty(0), prevProbability(0)
    {
    }

    KernelRecord(uint256 hash, int64_t nTime,
                 const std::string &address,
                 int64_t nValue, int idx, bool spent):
        hash(hash), nTime(nTime), address(address), nValue(nValue),
        idx(idx), spent(spent), prevMinutes(0), prevDifficulty(0), prevProbability(0)
    {
    }

    static bool showTransaction(bool isCoinbase, int depth);
    static std::vector<KernelRecord> decomposeOutput(interfaces::Wallet &wallet, const interfaces::WalletTx &wtx);


    uint256 hash;
    int64_t nTime;
    std::string address;
    int64_t nValue;
    int idx;
    bool spent;

    std::string getTxID();
    int64_t getAge() const;
    int64_t getCoinAge() const;
    double getProbToMintStake(double difficulty, int timeOffset = 0) const;
    double getProbToMintWithinNMinutes(double difficulty, int minutes);
protected:
    int prevMinutes;
    double prevDifficulty;
    double prevProbability;
};

#endif // PEERCOIN_KERNELRECORD_H
