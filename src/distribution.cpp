#include "util.h"
#include "bitcoinrpc.h"
#include "distribution.h"
#include "json/json_spirit_value.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace json_spirit;

void DividendDistributor::Distribute(double dDistributedAmount, double dMinimumPayout)
{
    if (mapBalance.size() == 0)
        throw runtime_error("The balance map is empty. There's not address to distribute dividends to.");

    BalanceMap mapRetainedBalance(mapBalance);
    bool bMustRedistribute = true;

    while (bMustRedistribute)
    {
        bMustRedistribute = false;

        dTotalDistributed = 0;
        vDistribution.clear();

        BalanceMap::iterator it;
        double dTotalBalance = 0;

        it = mapRetainedBalance.begin();
        while (it != mapRetainedBalance.end())
        {
            dTotalBalance += it->second;
            it++;
        }

        it = mapRetainedBalance.begin();
        while (it != mapRetainedBalance.end())
        {
            double dDistributed = it->second * dDistributedAmount / dTotalBalance;
            if (dDistributed < dMinimumPayout)
            {
                mapRetainedBalance.erase(it++);
                bMustRedistribute = true;
                continue;
            }
            Distribution distribution(it->first, it->second, dDistributed);
            vDistribution.push_back(distribution);

            dTotalDistributed += dDistributed;

            it++;
        }
    }
    if (dTotalDistributed == 0)
        throw runtime_error("No address received dividends.");

}

void DividendDistributor::GenerateOutputs(int nTransactions, vector<Object> &vTransactionOuts) const
{
    if (nTransactions <= 0)
        throw runtime_error("Invalid transaction count");

    if (vDistribution.size() == 0)
        throw runtime_error("No address to distribute to");

    if (nTransactions > vDistribution.size())
        throw runtime_error("Output split in too many transactions");

    vTransactionOuts.assign(nTransactions, Object());
    int nTransactionIndex = 0;

    BOOST_FOREACH(const Distribution &distribution, vDistribution)
    {
        double amount = distribution.GetDividendAmount();
        string address = distribution.GetPeercoinAddress().ToString();
        Object &out = vTransactionOuts[nTransactionIndex];

        out.push_back(Pair(address, (double)amount));
        nTransactionIndex = (nTransactionIndex + 1) % nTransactions;
    }
}

int DividendDistributor::GetTransactionCount(int nMaxDistributionPerTransaction) const
{
    return 1 + vDistribution.size() / nMaxDistributionPerTransaction;
}

double GetMinimumDividendPayout()
{
    return boost::lexical_cast<double>(GetArg("-distributionminpayout", "0.01"));
}

DividendDistributor GenerateDistribution(const BalanceMap &mapBalance, double dAmount)
{
    double dMinPayout = GetMinimumDividendPayout();

    printf("Distributing %f peercoins to %d addresses with a minimum payout of %f\n", dAmount, mapBalance.size(), dMinPayout);

    try {
        DividendDistributor distributor(mapBalance);
        distributor.Distribute(dAmount, dMinPayout);
        return distributor;
    }
    catch (runtime_error &e)
    {
        printf("Distribution failed: %s\n", e.what());
        throw;
    }
}

int GetMaximumDistributionPerTransaction()
{
    // As of 2014-02-22, Peercoin won't generate transactions larger than 100,000 bytes (MAX_BLOCK_SIZE_GEN/5)
    // https://github.com/ppcoin/ppcoin/blob/master/src/wallet.cpp#L1181
    // Each (non compressed) input takes 180 bytes, each output 34, and max 50 extra bytes
    // http://bitcoin.stackexchange.com/a/3011/9199
    // So 1000 outputs leaves room for about 350 inputs
    return GetArg("-maxdistributionpertransaction", 1000);
}

Array SendDistribution(const DividendDistributor &distributor)
{
    try {
        double dTotalDistributed = distributor.TotalDistributed();
        int nDistributionCount = distributor.DistributionCount();
        double dBalance = GetDistributionBalance();

        if (dTotalDistributed > dBalance)
            throw runtime_error("Not enough peercoins available in distribution account");

        int nMaxDistributionPerTransaction = GetMaximumDistributionPerTransaction();
        printf("Maximum output per transaction: %d\n", nMaxDistributionPerTransaction);

        int nTransactions = distributor.GetTransactionCount(nMaxDistributionPerTransaction);

        printf("Will send %f peercoins to %d addresses in %d transactions\n", dTotalDistributed, nDistributionCount, nTransactions);

        vector<Object> vOutputs;
        distributor.GenerateOutputs(nTransactions, vOutputs);

        int i = 0;
        BOOST_FOREACH(Object &output, vOutputs)
        {
            printf("Output %d:\n", i);
            printf("%s\n", write_string(Value(output), true).c_str());
            i++;
        }

        string sAccount = GetArg("-distributionaccount", "");

        i = 0;
        Array results;
        BOOST_FOREACH(Object &output, vOutputs)
        {
            Array sendmanyParams;
            sendmanyParams.push_back(sAccount);
            sendmanyParams.push_back(output);
            std::string result;
            printf("Sending output %d from account \"%s\"\n", i, sAccount.c_str());
            result = CallPeercoinRPC("sendmany", sendmanyParams);
            printf("Successfully sent output %d: %s\n", i, result.c_str());
            results.push_back(result);
            i++;
        }

        return results;
    }
    catch (runtime_error &e)
    {
        printf("Distribution failed: %s\n", e.what());
        throw;
    }
}

double GetDistributionBalance()
{
    string sAccount = GetArg("-distributionaccount", "");

    Array params;
    params.push_back(sAccount);
    return boost::lexical_cast<double>(Value(CallPeercoinRPC("getbalance", params)).get_str());
}
