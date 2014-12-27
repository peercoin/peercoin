#include <boost/test/unit_test.hpp>

#include "main.h"
#include "script.h"
#include "keystore.h"

using namespace std;

typedef vector<unsigned char> valtype;
CBigNum CastToBigNum(const valtype& vch);
bool CastToBool(const valtype& vch);


BOOST_AUTO_TEST_SUITE(cold_minting_tests)

BOOST_AUTO_TEST_CASE(op_coinstake)
{
    CTransaction txprev;
    CScript prevScript;
    prevScript << OP_NOP1;
    txprev.vout.push_back(CTxOut(1000 * COIN, prevScript));
    pcoinsTip->SetCoins(txprev.GetHash(), CCoins(txprev, 0));

    CScript script;
    script << OP_MINT;

    {
        // CoinStake that sends the same amount to the same script
        CTransaction tx;
        tx.vin.push_back(CTxIn(txprev.GetHash(), 0));
        tx.vout.push_back(CTxOut(0, CScript()));
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue / 2, prevScript));
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue / 2, prevScript));
        BOOST_CHECK(tx.IsCoinStake());

        vector<vector<unsigned char> > stack;
        BOOST_CHECK(EvalScript(stack, script, tx, 0, 0, 0));
        BOOST_CHECK(stack.size() == 1);
        BOOST_CHECK(CastToBigNum(stack[0]) == 1);
    }

    {
        // CoinStake with a total output < total input
        CTransaction tx;
        tx.nTime = txprev.nTime + 10 * 24 * 60 * 60;
        tx.vin.push_back(CTxIn(txprev.GetHash(), 0));
        tx.vout.push_back(CTxOut(0, CScript()));
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue - 1, prevScript));
        BOOST_CHECK(tx.IsCoinStake());

        vector<vector<unsigned char> > stack;
        BOOST_CHECK(EvalScript(stack, script, tx, 0, 0, 0));
        BOOST_CHECK(stack.size() == 1);
        BOOST_CHECK(CastToBigNum(stack[0]) == 0);
    }

    {
        // CoinStake with a different output script
        CTransaction tx;
        tx.nTime = txprev.nTime + 10 * 24 * 60 * 60;
        tx.vin.push_back(CTxIn(txprev.GetHash(), 0));
        tx.vout.push_back(CTxOut(0, CScript()));
        CScript otherScript;
        otherScript << OP_NOP2;
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue, otherScript));
        BOOST_CHECK(tx.IsCoinStake());

        vector<vector<unsigned char> > stack;
        BOOST_CHECK(EvalScript(stack, script, tx, 0, 0, 0));
        BOOST_CHECK(stack.size() == 1);
        BOOST_CHECK(CastToBigNum(stack[0]) == 0);
    }

    {
        // Not a CoinStake
        CTransaction tx;
        tx.vin.push_back(CTxIn(txprev.GetHash(), 0));
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue / 2, prevScript));
        tx.vout.push_back(CTxOut(txprev.vout[0].nValue / 2, prevScript));
        BOOST_CHECK(!tx.IsCoinStake());

        vector<vector<unsigned char> > stack;
        BOOST_CHECK(EvalScript(stack, script, tx, 0, 0, 0));
        BOOST_CHECK(stack.size() == 1);
        BOOST_CHECK(CastToBigNum(stack[0]) == 0);
    }
}

BOOST_AUTO_TEST_CASE(minting_script)
{
    CKey mintingKey;
    mintingKey.MakeNewKey(false);

    CKey spendingKey;
    spendingKey.MakeNewKey(false);

    CScript scriptMinting;
    scriptMinting.SetColdMinting(mintingKey.GetPubKey().GetID(), spendingKey.GetPubKey().GetID());
    BOOST_CHECK(IsStandard(scriptMinting));

    CTransaction txFrom;
    txFrom.vout.push_back(CTxOut(1000, scriptMinting));
    pcoinsTip->SetCoins(txFrom.GetHash(), CCoins(txFrom, 0));

    CTransaction txCoinStake;
    txCoinStake.vin.push_back(CTxIn(txFrom.GetHash(), 0));
    txCoinStake.vout.push_back(CTxOut(0, CScript()));
    txCoinStake.vout.push_back(CTxOut(1000, scriptMinting));
    BOOST_CHECK(txCoinStake.IsCoinStake());

    CTransaction txNonCoinStake;
    txNonCoinStake.vin.push_back(CTxIn(txFrom.GetHash(), 0));
    BOOST_CHECK(!txNonCoinStake.IsCoinStake());

    CBasicKeyStore keystoreMinting;
    keystoreMinting.AddKey(mintingKey);

    CBasicKeyStore keystoreSpending;
    keystoreSpending.AddKey(spendingKey);

    CBasicKeyStore keystoreBoth;
    keystoreBoth.AddKey(mintingKey);
    keystoreBoth.AddKey(spendingKey);

    CCoins coinsFrom(txFrom, MEMPOOL_HEIGHT);

    // we only have the minting key and the transaction is a CoinStake
    BOOST_CHECK(SignSignature(keystoreMinting, txFrom, txCoinStake, 0));
    BOOST_CHECK(VerifySignature(coinsFrom, txCoinStake, 0, 0, 0));

    // we only have the spending key and the transaction is a CoinStake
    BOOST_CHECK(!SignSignature(keystoreSpending, txFrom, txCoinStake, 0));
    BOOST_CHECK(!VerifySignature(coinsFrom, txCoinStake, 0, 0, 0));

    // we only have the minting key and the transaction is not a CoinStake
    BOOST_CHECK(!SignSignature(keystoreMinting, txFrom, txNonCoinStake, 0));
    BOOST_CHECK(!VerifySignature(coinsFrom, txNonCoinStake, 0, 0, 0));

    // we only have the spending key and the transaction is not a CoinStake
    BOOST_CHECK(SignSignature(keystoreSpending, txFrom, txNonCoinStake, 0));
    BOOST_CHECK(VerifySignature(coinsFrom, txNonCoinStake, 0, 0, 0));

    // we have both keys and the transaction is a CoinStake
    BOOST_CHECK(SignSignature(keystoreBoth, txFrom, txCoinStake, 0));
    BOOST_CHECK(VerifySignature(coinsFrom, txCoinStake, 0, 0, 0));

    // we have both keys and the transaction is not a CoinStake
    BOOST_CHECK(SignSignature(keystoreBoth, txFrom, txNonCoinStake, 0));
    BOOST_CHECK(VerifySignature(coinsFrom, txNonCoinStake, 0, 0, 0));
}

BOOST_AUTO_TEST_SUITE_END()

