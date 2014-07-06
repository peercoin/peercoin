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
    CTransaction txCoinStake;
    txCoinStake.vin.push_back(CTxIn(uint256(123), 0));
    txCoinStake.vout.push_back(CTxOut(0, CScript()));
    txCoinStake.vout.push_back(CTxOut());
    BOOST_CHECK(txCoinStake.IsCoinStake());

    CTransaction txNonCoinStake;
    BOOST_CHECK(!txNonCoinStake.IsCoinStake());

    vector<vector<unsigned char> > stack;

    CScript script;
    script << OP_COINSTAKE;

    BOOST_CHECK(EvalScript(stack, script, txCoinStake, 0, 0, 0));
    BOOST_CHECK(stack.size() == 1);
    BOOST_CHECK(CastToBigNum(stack[0]) == 1);

    stack.clear();

    BOOST_CHECK(EvalScript(stack, script, txNonCoinStake, 0, 0, 0));
    BOOST_CHECK(stack.size() == 1);
    BOOST_CHECK(CastToBigNum(stack[0]) == 0);
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

    CTransaction txCoinStake;
    txCoinStake.vin.push_back(CTxIn(txFrom.GetHash(), 0));
    txCoinStake.vout.push_back(CTxOut(0, CScript()));
    txCoinStake.vout.push_back(CTxOut());
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

