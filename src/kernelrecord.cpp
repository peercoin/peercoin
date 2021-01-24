#include <kernelrecord.h>
#include <key_io.h>
#include <wallet/wallet.h>
#include <base58.h>
#include <chainparams.h>
#include <timedata.h>
#include <interfaces/wallet.h>
#include <math.h>
using namespace std;

bool KernelRecord::showTransaction(bool isCoinbase, int depth)
{
    if (isCoinbase) {
        if (depth < 2)
            return false;
    } else {
        if (depth == 0)
            return false;
    }

    return true;
}

/*
 * Decompose CWallet transaction to model kernel records.
 */
vector<KernelRecord> KernelRecord::decomposeOutput(interfaces::Wallet& wallet, const interfaces::WalletTx &wtx)
{
    vector<KernelRecord> parts;
    int64_t nTime = wtx.tx->nTime;
    uint256 hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    int numBlocks;
    interfaces::WalletTxStatus status;
    interfaces::WalletOrderForm orderForm;
    bool inMempool;
    wallet.getWalletTxDetails(hash, status, orderForm, inMempool, numBlocks);

    if (showTransaction(wtx.is_coinbase, status.depth_in_main_chain)) {
        for (size_t nOut = 0; nOut < wtx.tx->vout.size(); nOut++) {
            CTxOut txOut = wtx.tx->vout[nOut];
            if (wallet.txoutIsMine(txOut)) {
                CTxDestination address;
                std::string addrStr;

                if (ExtractDestination(txOut.scriptPubKey, address)) {
                    // Sent to Bitcoin Address
                    addrStr = EncodeDestination(address);
                } else {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    addrStr = mapValue["to"];
                }
                std::vector<interfaces::WalletTxOut> coins = wallet.getCoins({COutPoint(hash, nOut)});
                bool isSpent = coins.size() >= 1 ? coins[0].is_spent : true;
                parts.push_back(KernelRecord(hash, nTime, addrStr, txOut.nValue, nOut, isSpent));
            }
        }
    }

    return parts;
}

std::string KernelRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}

int64_t KernelRecord::getAge() const
{
    return (GetAdjustedTime() - nTime) / 86400;
}

int64_t KernelRecord::getCoinAge() const
{
    const Consensus::Params& params = Params().GetConsensus();
    int nDayWeight = (min((GetAdjustedTime() - nTime), params.nStakeMaxAge) - params.nStakeMinAge) / 86400;
    return max(nValue * nDayWeight / COIN, (int64_t) 0);
}

double KernelRecord::getProbToMintStake(double difficulty, int timeOffset) const
{
    const Consensus::Params& params = Params().GetConsensus();
    double maxTarget = pow(static_cast<double>(2), 224);
    double target = maxTarget / difficulty;
    int dayWeight = (min((GetAdjustedTime() - nTime) + timeOffset, params.nStakeMaxAge) - params.nStakeMinAge) / 86400;
    uint64_t coinAge = max(nValue * dayWeight / COIN, (int64_t)0);
    return target * coinAge / pow(static_cast<double>(2), 256);
}

double KernelRecord::getProbToMintWithinNMinutes(double difficulty, int minutes)
{
    if(difficulty != prevDifficulty || minutes != prevMinutes)
    {
        double prob = 1;
        double p;
        int d = minutes / (60 * 24); // Number of full days
        int m = minutes % (60 * 24); // Number of minutes in the last day
        int i, timeOffset;

        // Probabilities for the first d days
        for(i = 0; i < d; i++)
        {
            timeOffset = i * 86400;
            p = pow(1 - getProbToMintStake(difficulty, timeOffset), 86400);
            prob *= p;
        }

        // Probability for the m minutes of the last day
        timeOffset = d * 86400;
        p = pow(1 - getProbToMintStake(difficulty, timeOffset), 60 * m);
        prob *= p;

        prob = 1 - prob;
        prevProbability = prob;
        prevDifficulty = difficulty;
        prevMinutes = minutes;
    }
    return prevProbability;
}
