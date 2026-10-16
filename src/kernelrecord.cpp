#include <kernelrecord.h>
#include <key_io.h>
#include <wallet/wallet.h>
#include <base58.h>
#include <chainparams.h>
#include <timedata.h>
#include <interfaces/wallet.h>
#include <algorithm>
#include <variant>
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

vector<KernelRecord> KernelRecord::decomposeOutput(interfaces::Wallet& wallet, const interfaces::WalletTx &wtx)
{
    int numBlocks;
    interfaces::WalletTxStatus status;
    interfaces::WalletOrderForm orderForm;
    bool inMempool;
    wallet.getWalletTxDetails(wtx.tx->GetHash(), status, orderForm, inMempool, numBlocks);
    return decomposeOutput(wallet, wtx, status.depth_in_main_chain);
}

/*
 * Decompose CWallet transaction to model kernel records.
 */
vector<KernelRecord> KernelRecord::decomposeOutput(interfaces::Wallet& wallet, const interfaces::WalletTx &wtx, int depth)
{
    vector<KernelRecord> parts;
    int64_t nTime = (wtx.tx->nTime ? wtx.tx->nTime : wtx.time);
    Txid hash = wtx.tx->GetHash();
    const std::map<std::string, std::string>& mapValue = wtx.value_map;

    if (showTransaction(wtx.is_coinbase, depth)) {
        for (size_t nOut = 0; nOut < wtx.tx->vout.size(); nOut++) {
            CTxOut txOut = wtx.tx->vout[nOut];
            if (wallet.txoutIsMine(txOut)) {
                CTxDestination address;
                std::string addrStr;

                if (ExtractDestination(txOut.scriptPubKey, address)) {
                    // Sent to Bitcoin Address
                    addrStr = EncodeDestination(address);
                } else if (const auto pk_dest = std::get_if<PubKeyDestination>(&address)) {
                    // peercoin: legacy P2PK outputs still show their pubkey hash
                    addrStr = EncodeDestination(PKHash(pk_dest->GetPubKey()));
                } else {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    auto to_it = mapValue.find("to");
                    if (to_it != mapValue.end()) {
                        addrStr = to_it->second;
                    }
                }
                std::vector<interfaces::WalletTxOut> coins = wallet.getCoins({COutPoint(hash, nOut)});
                bool isSpent = coins.size() >= 1 ? coins[0].is_spent : true;
                parts.push_back(KernelRecord(hash.ToUint256(), nTime, addrStr, txOut.nValue, nOut, isSpent));
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
    return (TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) - nTime) / 86400;
}

int64_t KernelRecord::getCoinAge() const
{
    const Consensus::Params& params = Params().GetConsensus();
    const int64_t age = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) - nTime;
    const int64_t day_weight = (std::min(age, params.nStakeMaxAge) - params.nStakeMinAge) / 86400;
    return std::max(nValue * day_weight / COIN, int64_t{0});
}

double KernelRecord::getProbToMintStake(double difficulty, int timeOffset) const
{
    const Consensus::Params& params = Params().GetConsensus();
    double maxTarget = pow(static_cast<double>(2), 224);
    double target = maxTarget / difficulty;
    const int64_t age = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) - nTime + timeOffset;
    const int64_t day_weight = (std::min(age, params.nStakeMaxAge) - params.nStakeMinAge) / 86400;
    const uint64_t coin_age = std::max(nValue * day_weight / COIN, int64_t{0});
    return target * coin_age / pow(static_cast<double>(2), 256);
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
