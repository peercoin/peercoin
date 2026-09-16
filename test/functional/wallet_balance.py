#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet balance RPC methods."""
from decimal import Decimal
import time

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE as ADDRESS_WATCHONLY
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hash_string,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import get_generate_key


def create_transactions(node, address, amt, fees):
    # Create and sign raw transactions from node to address for amt.
    # Creates a transaction for each fee and returns an array
    # of the raw transactions.
    utxos = [u for u in node.listunspent(0) if u['spendable']]

    # Create transactions
    inputs = []
    ins_total = 0
    for utxo in utxos:
        inputs.append({"txid": utxo["txid"], "vout": utxo["vout"]})
        ins_total += utxo['amount']
        if ins_total >= amt + max(fees):
            break
    # make sure there was enough utxos
    assert ins_total >= amt + max(fees)

    txs = []
    for fee in fees:
        outputs = {address: amt}
        # prevent 0 change output
        if ins_total > amt + fee:
            outputs[node.getrawchangeaddress()] = ins_total - amt - fee
        raw_tx = node.createrawtransaction(inputs, outputs, 0, True)
        raw_tx = node.signrawtransactionwithwallet(raw_tx)
        assert_equal(raw_tx['complete'], True)
        txs.append(raw_tx)

    return txs

class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.extra_args = [
            # Limit mempool clusters as a hack to have wallet txs rejected from the mempool.
            # Set walletrejectlongchains=0 so the wallet still creates the transactions.
            ['-limitclustercount=3', '-walletrejectlongchains=0'],
            [],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Mining blocks ...")
        self.generate(self.nodes[0], 1)
        self.generate(self.nodes[1], 1)

        # Verify listunspent returns immature coinbase if 'include_immature_coinbase' is set
        assert_equal(len(self.nodes[0].listunspent(query_options={'include_immature_coinbase': True})), 1)
        assert_equal(len(self.nodes[0].listunspent(query_options={'include_immature_coinbase': False})), 0)

        self.generatetoaddress(self.nodes[1], COINBASE_MATURITY + 1, ADDRESS_WATCHONLY)

        # Verify listunspent returns all immature coinbases if 'include_immature_coinbase' is set
        assert_equal(len(self.nodes[0].listunspent(query_options={'include_immature_coinbase': False})), 1)
        assert_equal(len(self.nodes[0].listunspent(query_options={'include_immature_coinbase': True})), 1)

        self.log.info("Test getbalance with different arguments")
        assert_equal(self.nodes[0].getbalance("*"), 50)
        assert_equal(self.nodes[0].getbalance("*", 1), 50)
        assert_equal(self.nodes[0].getbalance(minconf=1), 50)
        assert_equal(self.nodes[0].getbalance(minconf=0), 50)
        assert_equal(self.nodes[0].getbalance("*", 1, True), 50)
        assert_equal(self.nodes[1].getbalance(minconf=0), 50)

        # Send 40 BTC from 0 to 1 and 60 BTC from 1 to 0.
        txs = create_transactions(self.nodes[0], self.nodes[1].getnewaddress(), 40, [Decimal('0.01')])
        self.nodes[0].sendrawtransaction(txs[0]['hex'])
        self.nodes[1].sendrawtransaction(txs[0]['hex'])  # sending on both nodes is faster than waiting for propagation

        self.sync_all()
        txs = create_transactions(self.nodes[1], self.nodes[0].getnewaddress(), 60, [Decimal('0.01')])
        self.nodes[1].sendrawtransaction(txs[0]['hex'])
        self.nodes[0].sendrawtransaction(txs[0]['hex'])  # sending on both nodes is faster than waiting for propagation
        self.sync_all()

        # First argument of getbalance must be set to "*"
        assert_raises_rpc_error(-32, "dummy first argument must be excluded or set to \"*\"", self.nodes[1].getbalance, "")

        self.log.info("Test balances with unconfirmed inputs")

        # Before `test_balance()`, we have had two nodes with a balance of 50
        # each and then we:
        #
        # 1) Sent 40 from node A to node B with fee 0.01
        # 2) Sent 60 from node B to node A with fee 0.01
        #
        # Then we check the balances:
        #
        # 1) As is
        # 2) With transaction 2 from above with 2x the fee
        #
        # Prior to #16766, in this situation, the node would immediately report
        # a balance of 30 on node B as unconfirmed and trusted.
        #
        # After #16766, we show that balance as unconfirmed.
        #
        # The balance is indeed "trusted" and "confirmed" insofar as removing
        # the mempool transactions would return at least that much money. But
        # the algorithm after #16766 marks it as unconfirmed because the 'taint'
        # tracking of transaction trust for summing balances doesn't consider
        # which inputs belong to a user. In this case, the change output in
        # question could be "destroyed" by replace the 1st transaction above.
        #
        # The post #16766 behavior is correct; we shouldn't be treating those
        # funds as confirmed. If you want to rely on that specific UTXO existing
        # which has given you that balance, you cannot, as a third party
        # spending the other input would destroy that unconfirmed.
        #
        # For example, if the test transactions were:
        #
        # 1) Sent 40 from node A to node B with fee 0.01
        # 2) Sent 10 from node B to node A with fee 0.01
        #
        # Then our node would report a confirmed balance of 40 + 50 - 10 = 80
        # BTC, which is more than would be available if transaction 1 were
        # replaced.


        def test_balances():
            # getbalances
            expected_balances_0 = {'mine':      {'immature':          Decimal('0E-8'),
                                                 'trusted':           Decimal('9.99'),  # change from node 0's send
                                                 'untrusted_pending': Decimal('60.0')}}
            expected_balances_1 = {'mine':      {'immature':          Decimal('0E-8'),
                                                 'trusted':           Decimal('0E-8'),  # node 1's send had an unsafe input
                                                 'untrusted_pending': Decimal('30.0') - Decimal('0.01')}}  # Doesn't include output of node 0's send since it was spent
            balances_0 = self.nodes[0].getbalances()
            balances_1 = self.nodes[1].getbalances()
            # remove lastprocessedblock keys (they will be tested later)
            del balances_0['lastprocessedblock']
            del balances_1['lastprocessedblock']
            assert_equal(balances_0, expected_balances_0)
            assert_equal(balances_1, expected_balances_1)
            # getbalance without any arguments includes unconfirmed transactions, but not untrusted transactions
            assert_equal(self.nodes[0].getbalance(), Decimal('9.99'))  # change from node 0's send
            assert_equal(self.nodes[1].getbalance(), Decimal('0'))  # node 1's send had an unsafe input
            # Same with minconf=0
            assert_equal(self.nodes[0].getbalance(minconf=0), Decimal('9.99'))
            assert_equal(self.nodes[1].getbalance(minconf=0), Decimal('0'))
            # getbalance with a minconf incorrectly excludes coins that have been spent more recently than the minconf blocks ago
            # TODO: fix getbalance tracking of coin spentness depth
            assert_equal(self.nodes[0].getbalance(minconf=1), Decimal('0'))
            assert_equal(self.nodes[1].getbalance(minconf=1), Decimal('0'))

        test_balances()

        # Peercoin currently disables transaction replacement, so the bumped
        # transaction and conflicted-unconfirmed-input checks are skipped.

        self.generatetoaddress(self.nodes[1], 1, ADDRESS_WATCHONLY)

        # balances are correct after the transactions are confirmed
        balance_node0 = Decimal('69.99')  # node 1's send plus change from node 0's send
        balance_node1 = Decimal('29.99')  # change from node 0's send
        assert_equal(self.nodes[0].getbalances()['mine']['trusted'], balance_node0)
        assert_equal(self.nodes[1].getbalances()['mine']['trusted'], balance_node1)
        assert_equal(self.nodes[0].getbalance(), balance_node0)
        assert_equal(self.nodes[1].getbalance(), balance_node1)

        # Send total balance away from node 1
        txs = create_transactions(self.nodes[1], self.nodes[0].getnewaddress(), Decimal('29.97'), [Decimal('0.01')])
        self.nodes[1].sendrawtransaction(txs[0]['hex'])
        self.generatetoaddress(self.nodes[1], 2, ADDRESS_WATCHONLY)

        # Peercoin tracks confirmation depth differently; the Bitcoin getbalance
        # depth TODO assertions do not apply.

        # check mempool transactions count for wallet unconfirmed balance after
        # dynamically loading the wallet.
        before = self.nodes[1].getbalances()['mine']['untrusted_pending']
        dst = self.nodes[1].getnewaddress()
        self.nodes[1].unloadwallet(self.default_wallet_name)
        self.nodes[0].sendtoaddress(dst, 0.1)
        self.sync_all()
        self.nodes[1].loadwallet(self.default_wallet_name)
        after = self.nodes[1].getbalances()['mine']['untrusted_pending']
        assert_equal(before + Decimal('0.1'), after)

        # Peercoin does not support RBF or descendant-based replacement checks.
        self.generate(self.nodes[0], 1)

        # Tests the lastprocessedblock JSON object in getbalances, getwalletinfo
        # and gettransaction by checking for valid hex strings and by comparing
        # the hashes & heights between generated blocks.
        self.log.info("Test getbalances returns expected lastprocessedblock json object")
        prev_hash = self.nodes[0].getbestblockhash()
        prev_height = self.nodes[0].getblock(prev_hash)['height']
        self.generatetoaddress(self.nodes[0], 5, self.nodes[0].get_deterministic_priv_key().address)
        lastblock = self.nodes[0].getbalances()['lastprocessedblock']
        assert_is_hash_string(lastblock['hash'])
        assert_equal((prev_hash == lastblock['hash']), False)
        assert_equal(lastblock['height'], prev_height + 5)

        prev_hash = self.nodes[0].getbestblockhash()
        prev_height = self.nodes[0].getblock(prev_hash)['height']
        self.log.info("Test getwalletinfo returns expected lastprocessedblock json object")
        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['lastprocessedblock']['height'], prev_height)
        assert_equal(walletinfo['lastprocessedblock']['hash'], prev_hash)

        self.log.info("Test gettransaction returns expected lastprocessedblock json object")
        txid = self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(), 0.01)
        tx_info = self.nodes[1].gettransaction(txid)
        assert_equal(tx_info['lastprocessedblock']['height'], prev_height)
        assert_equal(tx_info['lastprocessedblock']['hash'], prev_hash)

        self.log.info("Test that the balance is updated by an import that makes an untracked output in an existing tx \"mine\"")
        default = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("importupdate")
        wallet = self.nodes[0].get_wallet_rpc("importupdate")

        import_key1 = get_generate_key()
        import_key2 = get_generate_key()
        wallet.importdescriptors([{"desc": descsum_create(f"wpkh({import_key1.privkey})"), "timestamp": "now"}])

        amount = 15
        default.send([{import_key1.p2wpkh_addr: amount},{import_key2.p2wpkh_addr: amount}])
        self.generate(self.nodes[0], 1)
        # Mock the time forward by 1 day so that "now" will exclude the block we just mined
        self.nodes[0].setmocktime(int(time.time()) + 86400)
        # Mine 11 blocks to move the MTP past the block we just mined
        self.generate(self.nodes[0], 11, sync_fun=self.no_op)

        balances = wallet.getbalances()
        assert_equal(balances["mine"]["trusted"], amount)

        # Don't rescan to make sure that the import updates the wallet txos
        wallet.importdescriptors([{"desc": descsum_create(f"wpkh({import_key2.privkey})"), "timestamp": "now"}])
        balances = wallet.getbalances()
        assert_equal(balances["mine"]["trusted"], amount * 2)

if __name__ == '__main__':
    WalletTest(__file__).main()
