#include <iostream>
#include <fstream>
#include <vector>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/foreach.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/test/unit_test.hpp>
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#include "main.h"
#include "wallet.h"

using namespace std;
using namespace json_spirit;
using namespace boost::algorithm;

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                         bool fValidatePayToScriptHash, int nHashType);

CScript
ParseScript(string s)
{
    CScript result;

    static map<string, opcodetype> mapOpNames;

    if (mapOpNames.size() == 0)
    {
        for (int op = OP_NOP; op <= OP_NOP10; op++)
        {
            const char* name = GetOpName((opcodetype)op);
            if (strcmp(name, "OP_UNKNOWN") == 0)
                continue;
            string strName(name);
            mapOpNames[strName] = (opcodetype)op;
            // Convenience: OP_ADD and just ADD are both recognized:
            replace_first(strName, "OP_", "");
            mapOpNames[strName] = (opcodetype)op;
        }
    }

    vector<string> words;
    split(words, s, is_any_of(" \t\n"), token_compress_on);

    BOOST_FOREACH(string w, words)
    {
        if (all(w, is_digit()) ||
            (starts_with(w, "-") && all(string(w.begin()+1, w.end()), is_digit())))
        {
            // Number
            int64 n = atoi64(w);
            result << n;
        }
        else if (starts_with(w, "0x") && IsHex(string(w.begin()+2, w.end())))
        {
            // Hex data:
            result << ParseHex(string(w.begin()+2, w.end()));
        }
        else if (s.size() >= 2 && starts_with(w, "'") && ends_with(w, "'"))
        {
            // Single-quoted string, pushed as data:
            std::vector<unsigned char> value(s.begin()+1, s.end()-1);
            result << value;
        }
        else if (mapOpNames.count(w))
        {
            // opcode, e.g. OP_ADD or OP_1:
            result << mapOpNames[w];
        }
        else
        {
            BOOST_ERROR("Parse error: " << s);
            return CScript();
        }                        
    }

    return result;
}

Array
read_json(const std::string& filename)
{
    namespace fs = boost::filesystem;
    fs::path testFile = fs::current_path() / "test" / "data" / filename;

#ifdef TEST_DATA_DIR
    if (!fs::exists(testFile))
    {
        testFile = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
    }
#endif

    ifstream ifs(testFile.string().c_str(), ifstream::in);
    Value v;
    if (!read_stream(ifs, v))
    {
        BOOST_ERROR("Cound not find/open " << filename);
        return Array();
    }
    if (v.type() != array_type)
    {
        BOOST_ERROR(filename << " does not contain a json array");
        return Array();
    }

    return v.get_array();
}

BOOST_AUTO_TEST_SUITE(script_tests)

BOOST_AUTO_TEST_CASE(script_dubious)
{
    // transaction 9c125157e9d246823885a93537ed42590cf19c8acb746ea4940999b7cf7b6bc7
    unsigned char chTo[] = {1, 0, 0, 0, 98, 236, 39, 87, 1, 114, 62, 74, 50, 35, 61, 126, 3, 42, 58, 247, 85, 117, 200, 24, 62, 42, 183, 226, 200, 37, 113, 128, 182, 6, 231, 181, 165, 166, 89, 240, 34, 1, 0, 0, 0, 72, 71, 48, 68, 2, 32, 9, 27, 112, 141, 116, 173, 6, 133, 22, 103, 254, 163, 75, 101, 153, 74, 9, 136, 70, 131, 117, 22, 16, 68, 200, 246, 210, 247, 77, 73, 66, 177, 2, 32, 30, 244, 146, 228, 213, 43, 144, 40, 58, 193, 120, 72, 55, 95, 88, 236, 122, 52, 155, 162, 0, 152, 254, 187, 214, 33, 170, 118, 72, 3, 186, 98, 1, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 100, 2, 0, 0, 0, 0, 35, 33, 3, 44, 57, 253, 162, 105, 96, 181, 35, 46, 82, 32, 249, 66, 252, 156, 214, 190, 113, 12, 235, 208, 251, 184, 133, 246, 101, 251, 39, 175, 192, 153, 228, 172, 0, 203, 100, 2, 0, 0, 0, 0, 35, 33, 3, 44, 57, 253, 162, 105, 96, 181, 35, 46, 82, 32, 249, 66, 252, 156, 214, 190, 113, 12, 235, 208, 251, 184, 133, 246, 101, 251, 39, 175, 192, 153, 228, 172, 0, 0, 0, 0, 0};
    // transaction fd38483a2029469fecdecfc08526b9e7d6635945d74adc92dc836aa7f6ea1291
    unsigned char chFrom[] = {1, 0, 0, 0, 88, 95, 34, 87, 3, 38, 187, 221, 58, 77, 170, 121, 39, 173, 134, 230, 135, 15, 8, 106, 50, 175, 21, 108, 228, 61, 238, 108, 20, 90, 51, 7, 204, 119, 194, 153, 197, 4, 0, 0, 0, 107, 72, 48, 69, 2, 32, 21, 65, 115, 78, 116, 220, 41, 34, 233, 192, 30, 25, 59, 168, 35, 189, 250, 74, 88, 79, 219, 15, 104, 235, 45, 101, 184, 249, 12, 132, 149, 48, 2, 33, 0, 207, 113, 77, 124, 81, 65, 42, 60, 75, 204, 199, 194, 90, 251, 125, 0, 85, 29, 75, 26, 7, 248, 183, 201, 130, 118, 66, 67, 157, 8, 124, 68, 1, 33, 2, 255, 157, 111, 234, 125, 30, 181, 87, 180, 77, 53, 250, 203, 115, 39, 154, 156, 141, 225, 217, 163, 53, 203, 29, 227, 139, 49, 30, 206, 60, 17, 168, 255, 255, 255, 255, 90, 47, 158, 133, 194, 154, 122, 62, 43, 108, 149, 90, 48, 254, 75, 177, 50, 82, 60, 105, 92, 79, 241, 6, 26, 84, 147, 109, 136, 10, 71, 145, 35, 0, 0, 0, 107, 72, 48, 69, 2, 32, 95, 195, 206, 125, 115, 193, 208, 253, 61, 30, 150, 10, 161, 45, 51, 154, 231, 132, 17, 64, 150, 167, 58, 113, 163, 155, 145, 166, 185, 163, 184, 210, 2, 33, 0, 146, 71, 213, 85, 47, 234, 200, 249, 229, 78, 206, 12, 89, 197, 229, 23, 117, 25, 21, 21, 200, 125, 62, 8, 106, 71, 170, 112, 38, 43, 239, 86, 1, 33, 3, 43, 45, 43, 145, 209, 252, 101, 56, 255, 115, 233, 215, 199, 94, 77, 103, 129, 34, 238, 236, 72, 163, 184, 11, 0, 35, 63, 24, 91, 155, 136, 121, 255, 255, 255, 255, 103, 170, 13, 15, 84, 203, 78, 84, 194, 137, 137, 35, 228, 204, 225, 243, 218, 198, 68, 226, 249, 232, 108, 1, 104, 35, 218, 44, 53, 159, 161, 73, 7, 0, 0, 0, 107, 72, 48, 69, 2, 32, 21, 73, 164, 43, 105, 119, 0, 241, 65, 134, 148, 205, 112, 125, 224, 230, 144, 17, 206, 49, 46, 71, 255, 188, 239, 140, 155, 104, 49, 27, 122, 57, 2, 33, 0, 225, 245, 254, 1, 119, 246, 242, 148, 61, 6, 139, 109, 19, 160, 246, 179, 92, 214, 217, 189, 112, 246, 31, 116, 226, 143, 147, 5, 172, 10, 251, 185, 1, 33, 2, 74, 5, 190, 229, 117, 14, 132, 121, 18, 172, 76, 192, 186, 104, 217, 0, 61, 74, 98, 49, 215, 211, 176, 252, 64, 84, 74, 180, 74, 245, 235, 177, 255, 255, 255, 255, 2, 17, 39, 0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 111, 165, 179, 70, 122, 64, 210, 30, 51, 42, 133, 85, 232, 77, 0, 8, 32, 140, 118, 116, 136, 172, 192, 212, 1, 0, 0, 0, 0, 0, 25, 118, 169, 20, 201, 170, 133, 68, 200, 48, 184, 102, 229, 25, 193, 36, 84, 101, 179, 149, 134, 62, 244, 68, 136, 172, 0, 0, 0, 0, 0};

    vector<unsigned char> vch(chTo, chTo + sizeof(chTo) -1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction txTo;
    stream >> txTo;

    vector<unsigned char> vch2(chFrom, chFrom + sizeof(chFrom) -1);
    CDataStream stream2(vch2, SER_DISK, CLIENT_VERSION);
    CTransaction txFrom;
    stream2 >> txFrom;

    BOOST_CHECK_MESSAGE(VerifySignature(txFrom, txTo, 0, true, 0), "verifySignature should pass.");
}

BOOST_AUTO_TEST_CASE(script_valid)
{
    // Read tests from test/data/script_valid.json
    // Format is an array of arrays
    // Inner arrays are [ "scriptSig", "scriptPubKey" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    Array tests = read_json("script_valid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test.size() < 2) // Allow size > 2; extra stuff ignored (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        string scriptSigString = test[0].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        string scriptPubKeyString = test[1].get_str();
        CScript scriptPubKey = ParseScript(scriptPubKeyString);

        CTransaction tx;
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, tx, 0, true, SIGHASH_NONE), strTest);
    }
}

BOOST_AUTO_TEST_CASE(script_invalid)
{
    // Scripts that should evaluate as invalid
    Array tests = read_json("script_invalid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test.size() < 2) // Allow size > 2; extra stuff ignored (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        string scriptSigString = test[0].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        string scriptPubKeyString = test[1].get_str();
        CScript scriptPubKey = ParseScript(scriptPubKeyString);

        CTransaction tx;
        BOOST_CHECK_MESSAGE(!VerifyScript(scriptSig, scriptPubKey, tx, 0, true, SIGHASH_NONE), strTest);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    vector<vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(&direct[0], &direct[sizeof(direct)]), CTransaction(), 0, 0));

    vector<vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(&pushdata1[0], &pushdata1[sizeof(pushdata1)]), CTransaction(), 0, 0));
    BOOST_CHECK(pushdata1Stack == directStack);

    vector<vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(&pushdata2[0], &pushdata2[sizeof(pushdata2)]), CTransaction(), 0, 0));
    BOOST_CHECK(pushdata2Stack == directStack);

    vector<vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(&pushdata4[0], &pushdata4[sizeof(pushdata4)]), CTransaction(), 0, 0));
    BOOST_CHECK(pushdata4Stack == directStack);
}

CScript
sign_multisig(CScript scriptPubKey, std::vector<CKey> keys, CTransaction transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the blockchain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    BOOST_FOREACH(CKey key, keys)
    {
        vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
CScript
sign_multisig(CScript scriptPubKey, CKey key, CTransaction transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    CKey key1, key2, key3;
    key1.MakeNewKey(true);
    key2.MakeNewKey(false);
    key3.MakeNewKey(true);

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << key1.GetPubKey() << key2.GetPubKey() << OP_2 << OP_CHECKMULTISIG;

    CTransaction txFrom12;
    txFrom12.vout.resize(1);
    txFrom12.vout[0].scriptPubKey = scriptPubKey12;

    CTransaction txTo12;
    txTo12.vin.resize(1);
    txTo12.vout.resize(1);
    txTo12.vin[0].prevout.n = 0;
    txTo12.vin[0].prevout.hash = txFrom12.GetHash();
    txTo12.vout[0].nValue = 1;

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, txTo12);
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, txTo12, 0, true, 0));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, txTo12, 0, true, 0));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, txTo12);
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, txTo12, 0, true, 0));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, txTo12);
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, txTo12, 0, true, 0));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    CKey key1, key2, key3, key4;
    key1.MakeNewKey(true);
    key2.MakeNewKey(false);
    key3.MakeNewKey(true);
    key4.MakeNewKey(false);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << key1.GetPubKey() << key2.GetPubKey() << key3.GetPubKey() << OP_3 << OP_CHECKMULTISIG;

    CTransaction txFrom23;
    txFrom23.vout.resize(1);
    txFrom23.vout[0].scriptPubKey = scriptPubKey23;

    CTransaction txTo23;
    txTo23.vin.resize(1);
    txTo23.vout.resize(1);
    txTo23.vin[0].prevout.n = 0;
    txTo23.vin[0].prevout.hash = txFrom23.GetHash();
    txTo23.vout[0].nValue = 1;

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't re-use sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, txTo23, 0, true, 0));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, txTo23);
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, txTo23, 0, true, 0));
}    


BOOST_AUTO_TEST_SUITE_END()
