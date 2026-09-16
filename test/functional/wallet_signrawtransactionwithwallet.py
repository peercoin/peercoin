#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction signing using the signrawtransactionwithwallet RPC."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
)
from test_framework.address import (
    script_to_p2wsh,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.messages import (
    CTxInWitness,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_TRUE,
)

from decimal import (
    Decimal,
    getcontext,
)


class SignRawTransactionWithWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_with_lock_outputs(self):
        self.log.info("Test correct error reporting when trying to sign a locked output")
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        raw_tx = self.nodes[0].fundrawtransaction(
            self.nodes[0].createrawtransaction([], [{self.nodes[0].getnewaddress(): 10}])
        )['hex']
        self.nodes[0].encryptwallet("password")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].signrawtransactionwithwallet, raw_tx)
        self.nodes[0].walletpassphrase("password", 9999)

    def test_with_invalid_sighashtype(self):
        self.log.info("Test signrawtransactionwithwallet raises if an invalid sighashtype is passed")
        raw_tx = self.nodes[0].fundrawtransaction(
            self.nodes[0].createrawtransaction([], [{self.nodes[0].getnewaddress(): 10}])
        )['hex']
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[0].signrawtransactionwithwallet, hexstring=raw_tx, sighashtype="all")

    def test_fully_signed_tx(self):
        self.log.info("Test signing a fully signed transaction does nothing")
        self.nodes[0].walletpassphrase("password", 9999)
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        rawtx = self.nodes[0].createrawtransaction([], [{self.nodes[0].getnewaddress(): 10}])
        fundedtx = self.nodes[0].fundrawtransaction(rawtx)
        signedtx = self.nodes[0].signrawtransactionwithwallet(fundedtx["hex"])
        assert_equal(signedtx["complete"], True)
        signedtx2 = self.nodes[0].signrawtransactionwithwallet(signedtx["hex"])
        assert_equal(signedtx2["complete"], True)
        assert_equal(signedtx["hex"], signedtx2["hex"])
        self.nodes[0].walletlock()

    def test_signing_with_missing_prevtx_info(self):
        self.nodes[0].walletpassphrase("password", 9999)
        txid = "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000"
        for type in ["bech32", "p2sh-segwit", "legacy"]:
            self.log.info(f"Test signing with missing prevtx info ({type})")
            addr = self.nodes[0].getnewaddress("", type)
            addrinfo = self.nodes[0].getaddressinfo(addr)
            pubkey = addrinfo["scriptPubKey"]
            inputs = [{'txid': txid, 'vout': 3, 'sequence': 1000}]
            outputs = {self.nodes[0].getnewaddress(): 1}
            rawtx = self.nodes[0].createrawtransaction(inputs, outputs)

            prevtx = dict(txid=txid, scriptPubKey=pubkey, vout=3, amount=1)
            succ = self.nodes[0].signrawtransactionwithwallet(rawtx, [prevtx])
            assert succ["complete"]

            if type == "legacy":
                del prevtx["amount"]
                succ = self.nodes[0].signrawtransactionwithwallet(rawtx, [prevtx])
                assert succ["complete"]
            else:
                assert_raises_rpc_error(-3, "Missing amount", self.nodes[0].signrawtransactionwithwallet, rawtx, [
                    {
                        "txid": txid,
                        "scriptPubKey": pubkey,
                        "vout": 3,
                    }
                ])

            assert_raises_rpc_error(-3, "Missing vout", self.nodes[0].signrawtransactionwithwallet, rawtx, [
                {
                    "txid": txid,
                    "scriptPubKey": pubkey,
                    "amount": 1,
                }
            ])
            assert_raises_rpc_error(-3, "Missing txid", self.nodes[0].signrawtransactionwithwallet, rawtx, [
                {
                    "scriptPubKey": pubkey,
                    "vout": 3,
                    "amount": 1,
                }
            ])
            assert_raises_rpc_error(-3, "Missing scriptPubKey", self.nodes[0].signrawtransactionwithwallet, rawtx, [
                {
                    "txid": txid,
                    "vout": 3,
                    "amount": 1
                }
            ])

    def run_test(self):
        self.test_with_lock_outputs()
        self.test_with_invalid_sighashtype()
        self.test_fully_signed_tx()
        self.test_signing_with_missing_prevtx_info()


if __name__ == '__main__':
    SignRawTransactionWithWalletTest(__file__).main()
