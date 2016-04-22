// Copyright (c) 2009-2012 Bitcoin Developers
// Copyright (c) 2012-2013 The Peercoin developers
// Copyright (c) 2013-2014 The Peershares developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"

#include <boost/lexical_cast.hpp>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#define printf OutputDebugStringF

// using namespace boost::asio;
using namespace json_spirit;
using namespace std;

extern Object JSONRPCError(int code, const string& message);

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "importprivkey <ppcoinprivkey> [label]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(-5,"Invalid private key");
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly) // peercoin: no importprivkey in mint-only mode
        throw JSONRPCError(-102, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CBitcoinAddress vchAddress = CBitcoinAddress(key.GetPubKey());

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(-4,"Error adding key to wallet");

        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
        pwalletMain->ReacceptWalletTransactions();
    }

    MainFrameRepaint();

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <ppcoinaddress>\n"
            "Reveals the private key corresponding to <ppcoinaddress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(-5, "Invalid ppcoin address");
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly) // peercoin: no dumpprivkey in mint-only mode
        throw JSONRPCError(-102, "Wallet is unlocked for minting only.");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(address, vchSecret, fCompressed))
        throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

Value exportpeercoinkeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "exportpeercoinkeys\n"
            "Add the Peercoin keys associated with the Peershares addresses to the Peercoin wallet. Peercoin must be running and accept RPC commands.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly) // peercoin: no dumpprivkey in mint-only mode
        throw JSONRPCError(-102, "Wallet is unlocked for minting only.");

    Object ret;
    int nExportedCount, nErrorCount;
    pwalletMain->ExportPeercoinKeys(nExportedCount, nErrorCount);
    ret.push_back(Pair("exported", nExportedCount));
    ret.push_back(Pair("failed", nErrorCount));
    return ret;
}
