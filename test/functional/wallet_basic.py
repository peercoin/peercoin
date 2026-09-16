#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet."""
from decimal import Decimal
from itertools import product

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_array_result,
    assert_equal,
    assert_fee_amount,
    assert_raises_rpc_error,
    find_vout_for_address,
)
from test_framework.wallet_util import test_address

NOT_A_NUMBER_OR_STRING = "Amount is not a number or string"
OUT_OF_RANGE = "Amount out of range"


class WalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [[
            "-dustrelayfee=0", "-walletrejectlongchains=0", "-whitelist=noban@127.0.0.1"
        ]] * self.num_nodes
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Only need nodes 0-2 running at start of test
        self.stop_node(3)
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.sync_all(self.nodes[0:3])

    def check_fee_amount(self, curr_balance, balance_with_fee, fee_per_byte, tx_size):
        """Return curr_balance after asserting the fee was in range"""
        fee = balance_with_fee - curr_balance
        assert_fee_amount(fee, tx_size, fee_per_byte * 1000)
        return curr_balance

    def get_vsize(self, txn):
        return self.nodes[0].decoderawtransaction(txn)['vsize']

    def tx_fee(self, node, txid):
        return abs(Decimal(str(node.gettransaction(txid)['fee'])))

    def pp_min_fee(self, size):
        return Decimal('0.001') if size < 100 else Decimal(size) * Decimal('0.00001')

    def check_pp_fee(self, node, txid):
        tx = self.nodes[0].decoderawtransaction(node.gettransaction(txid)['hex'])
        value_in = Decimal('0')
        for vin in tx['vin']:
            if 'coinbase' in vin or 'coinbasehex' in vin:
                continue
            prev = self.nodes[0].getrawtransaction(vin['txid'], True)
            value_in += Decimal(str(prev['vout'][vin['vout']]['value']))
        value_out = sum((Decimal(str(vout['value'])) for vout in tx['vout']), Decimal('0'))
        fee = value_in - value_out
        min_fee = self.pp_min_fee(tx['size'])
        assert fee >= min_fee
        return fee

    def recipient_output_value(self, txid, address):
        script = self.nodes[0].getaddressinfo(address)['scriptPubKey']
        tx = self.nodes[0].decoderawtransaction(self.nodes[2].gettransaction(txid)['hex'])
        return sum((Decimal(str(vout['value'])) for vout in tx['vout'] if vout['scriptPubKey']['hex'] == script), Decimal('0'))

    def expected_send_balances(self, sender_balance, recipient_balance, amount, fee, txid, address):
        sent = self.recipient_output_value(txid, address)
        sender_loss = amount if sent == amount - fee else amount + fee
        return sender_balance - sender_loss, recipient_balance + sent

    def check_pp_fee_hex(self, hex_tx):
        tx = self.nodes[0].decoderawtransaction(hex_tx)
        value_in = Decimal('0')
        for vin in tx['vin']:
            if 'coinbase' in vin or 'coinbasehex' in vin:
                continue
            prev = self.nodes[0].getrawtransaction(vin['txid'], True)
            value_in += Decimal(str(prev['vout'][vin['vout']]['value']))
        value_out = sum((Decimal(str(vout['value'])) for vout in tx['vout']), Decimal('0'))
        fee = value_in - value_out
        assert fee >= self.pp_min_fee(tx['size'])
        return fee

    def check_pp_funded_psbt_fee(self, result):
        fee = Decimal(str(result['fee']))
        assert fee >= Decimal('0.001')
        return fee

    def node_args_with(self, i, overrides):
        names = {arg.split('=', 1)[0] for arg in overrides}
        return [arg for arg in self.nodes[i].extra_args if arg.split('=', 1)[0] not in names] + overrides

    def run_test(self):

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        self.log.info("Mining blocks...")

        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        balances = self.nodes[0].getbalances()
        assert_equal(balances["mine"]["immature"], 50)
        assert_equal(balances["mine"]["trusted"], 0)

        self.sync_all(self.nodes[0:3])
        self.generate(self.nodes[1], COINBASE_MATURITY + 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))

        coinbase_reward = Decimal(str(self.nodes[0].getbalance()))
        assert coinbase_reward > 0
        assert_equal(self.nodes[1].getbalance(), coinbase_reward)
        assert_equal(self.nodes[2].getbalance(), 0)

        # Check that only first and second nodes have UTXOs
        utxos = self.nodes[0].listunspent()
        assert_equal(len(utxos), 1)
        assert_equal(len(self.nodes[1].listunspent()), 1)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        self.log.info("Test gettxout")
        confirmed_txid, confirmed_index = utxos[0]["txid"], utxos[0]["vout"]
        # First, outputs that are unspent both in the chain and in the
        # mempool should appear with or without include_mempool
        txout = self.nodes[0].gettxout(txid=confirmed_txid, n=confirmed_index, include_mempool=False)
        assert_equal(txout['value'], 50)
        txout = self.nodes[0].gettxout(txid=confirmed_txid, n=confirmed_index, include_mempool=True)
        assert_equal(txout['value'], 50)

        # Send 21 BTC from 0 to 2 using sendtoaddress call.
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 11)
        mempool_txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 10)

        self.log.info("Test gettxout (second part)")
        # utxo spent in mempool should be visible if you exclude mempool
        # but invisible if you include mempool
        txout = self.nodes[0].gettxout(confirmed_txid, confirmed_index, False)
        assert_equal(txout['value'], 50)
        txout = self.nodes[0].gettxout(confirmed_txid, confirmed_index)  # by default include_mempool=True
        assert txout is None
        txout = self.nodes[0].gettxout(confirmed_txid, confirmed_index, True)
        assert txout is None
        # new utxo from mempool should be invisible if you exclude mempool
        # but visible if you include mempool
        txout = self.nodes[0].gettxout(mempool_txid, 0, False)
        assert txout is None
        txout1 = self.nodes[0].gettxout(mempool_txid, 0, True)
        txout2 = self.nodes[0].gettxout(mempool_txid, 1, True)
        # note the mempool tx will have randomly assigned indices
        # but 10 will go to node2 and the rest will go to node0
        balance = self.nodes[0].getbalance()
        assert_equal(set([txout1['value'], txout2['value']]), set([10, balance]))
        assert_equal(self.nodes[0].getbalances()["mine"]["immature"], 0)

        # Have node0 mine a block, thus it will collect its own fee.
        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        node0_balance_after_fees = Decimal(str(self.nodes[0].getbalance()))
        node2_balance_after_fees = Decimal(str(self.nodes[2].getbalance()))

        # Exercise locking of unspent outputs
        unspent_0 = self.nodes[2].listunspent()[0]
        unspent_0 = {"txid": unspent_0["txid"], "vout": unspent_0["vout"]}
        # Trying to unlock an output which isn't locked should error
        assert_raises_rpc_error(-8, "Invalid parameter, expected locked output", self.nodes[2].lockunspent, True, [unspent_0])

        # Locking an already-locked output should error
        self.nodes[2].lockunspent(False, [unspent_0])
        assert_raises_rpc_error(-8, "Invalid parameter, output already locked", self.nodes[2].lockunspent, False, [unspent_0])

        # Restarting the node should clear the lock
        self.restart_node(2)
        self.nodes[2].lockunspent(False, [unspent_0])

        # Unloading and reloating the wallet should clear the lock
        assert_equal(self.nodes[0].listwallets(), [self.default_wallet_name])
        self.nodes[2].unloadwallet(self.default_wallet_name)
        self.nodes[2].loadwallet(self.default_wallet_name)
        assert_equal(len(self.nodes[2].listlockunspent()), 0)

        # Locking non-persistently, then re-locking persistently, is allowed
        self.nodes[2].lockunspent(False, [unspent_0])
        self.nodes[2].lockunspent(False, [unspent_0], True)

        # Restarting the node with the lock written to the wallet should keep the lock
        self.restart_node(2, self.node_args_with(2, ["-walletrejectlongchains=0"]))
        assert_raises_rpc_error(-8, "Invalid parameter, output already locked", self.nodes[2].lockunspent, False, [unspent_0])

        # Unloading and reloading the wallet with a persistent lock should keep the lock
        self.nodes[2].unloadwallet(self.default_wallet_name)
        self.nodes[2].loadwallet(self.default_wallet_name)
        assert_raises_rpc_error(-8, "Invalid parameter, output already locked", self.nodes[2].lockunspent, False, [unspent_0])

        # Locked outputs should not be used, even if they are the only available funds
        assert_raises_rpc_error(-6, "Insufficient funds", self.nodes[2].sendtoaddress, self.nodes[2].getnewaddress(), 20)
        assert_equal([unspent_0], self.nodes[2].listlockunspent())

        # Unlocking should remove the persistent lock
        self.nodes[2].lockunspent(True, [unspent_0])
        self.restart_node(2)
        assert_equal(len(self.nodes[2].listlockunspent()), 0)

        # Reconnect node 2 after restarts
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)

        assert_raises_rpc_error(-8, "txid must be of length 64 (not 34, for '0000000000000000000000000000000000')",
                                self.nodes[2].lockunspent, False,
                                [{"txid": "0000000000000000000000000000000000", "vout": 0}])
        assert_raises_rpc_error(-8, "txid must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')",
                                self.nodes[2].lockunspent, False,
                                [{"txid": "ZZZ0000000000000000000000000000000000000000000000000000000000000", "vout": 0}])
        assert_raises_rpc_error(-8, "Invalid parameter, unknown transaction",
                                self.nodes[2].lockunspent, False,
                                [{"txid": "0000000000000000000000000000000000000000000000000000000000000000", "vout": 0}])
        assert_raises_rpc_error(-8, "Invalid parameter, vout index out of bounds",
                                self.nodes[2].lockunspent, False,
                                [{"txid": unspent_0["txid"], "vout": 999}])

        # The lock on a manually selected output is ignored
        unspent_0 = self.nodes[1].listunspent()[0]
        self.nodes[1].lockunspent(False, [unspent_0])
        tx = self.nodes[1].createrawtransaction([unspent_0], { self.nodes[1].getnewaddress() : 1 })
        self.nodes[1].fundrawtransaction(tx,{"lockUnspents": True})

        # fundrawtransaction can lock an input
        self.nodes[1].lockunspent(True, [unspent_0])
        assert_equal(len(self.nodes[1].listlockunspent()), 0)
        tx = self.nodes[1].fundrawtransaction(tx,{"lockUnspents": True})['hex']
        assert_equal(len(self.nodes[1].listlockunspent()), 1)

        # Send transaction
        tx = self.nodes[1].signrawtransactionwithwallet(tx)["hex"]
        self.nodes[1].sendrawtransaction(tx)
        assert_equal(len(self.nodes[1].listlockunspent()), 0)

        # Node0 mined one block before this phase; it matures after COINBASE_MATURITY more blocks.
        self.generate(self.nodes[1], COINBASE_MATURITY, sync_fun=lambda: self.sync_all(self.nodes[0:3]))

        assert_equal(self.nodes[0].getbalance(), node0_balance_after_fees + coinbase_reward)
        assert_equal(self.nodes[2].getbalance(), node2_balance_after_fees)

        # Sweep all mature outputs from node0.
        node0utxos = self.nodes[0].listunspent(1)
        assert len(node0utxos) > 0

        # create both transactions
        txns_to_send = []
        expected_node2_balance_after_sweep = node2_balance_after_fees
        for utxo in node0utxos:
            inputs = []
            outputs = {}
            sent_amount = Decimal(str(utxo["amount"])) - 3
            assert sent_amount > 0
            inputs.append({"txid": utxo["txid"], "vout": utxo["vout"]})
            outputs[self.nodes[2].getnewaddress()] = sent_amount
            expected_node2_balance_after_sweep += sent_amount
            raw_tx = self.nodes[0].createrawtransaction(inputs, outputs)
            txns_to_send.append(self.nodes[0].signrawtransactionwithwallet(raw_tx))

        # Have node 1 (miner) send the transactions
        self.nodes[1].sendrawtransaction(hexstring=txns_to_send[0]["hex"], maxfeerate=0)
        self.nodes[1].sendrawtransaction(hexstring=txns_to_send[1]["hex"], maxfeerate=0)

        # Have node1 mine a block to confirm transactions:
        self.generate(self.nodes[1], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))

        assert_equal(self.nodes[0].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), expected_node2_balance_after_sweep)

        # Verify that a spent output cannot be locked anymore
        spent_0 = {"txid": node0utxos[0]["txid"], "vout": node0utxos[0]["vout"]}
        assert_raises_rpc_error(-8, "Invalid parameter, expected unspent output", self.nodes[0].lockunspent, False, [spent_0])

        # Send 10 coins with Peercoin's fixed minimum fee.
        address = self.nodes[0].getnewaddress("test")
        node_2_bal = Decimal(str(self.nodes[2].getbalance()))
        node_0_bal = Decimal(str(self.nodes[0].getbalance()))
        txid = self.nodes[2].sendtoaddress(address, 10, "", "", False)
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal, node_0_bal, Decimal('10'), fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        # Send 10 coins with subtract fee from amount
        node_2_bal_before = node_2_bal
        node_0_bal_before = node_0_bal
        txid = self.nodes[2].sendtoaddress(address, 10, "", "", True)
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal_before, node_0_bal_before, Decimal('10'), fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        self.log.info("Test sendmany")

        # Sendmany 10 coins
        node_2_bal_before = node_2_bal
        node_0_bal_before = node_0_bal
        txid = self.nodes[2].sendmany('', {address: 10}, 0, "", [])
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal_before, node_0_bal_before, Decimal('10'), fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        # Sendmany 10 coins (fee-subtraction is checked via the recipient output value)
        node_2_bal_before = node_2_bal
        node_0_bal_before = node_0_bal
        txid = self.nodes[2].sendmany('', {address: 10}, 0, "", [address])
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal_before, node_0_bal_before, Decimal('10'), fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        self.log.info("Test sendmany with fee_rate param (explicit fee rate)")
        fee_rate = 2
        fee_rate_per_byte = Decimal(fee_rate) * Decimal('0.00001')

        # Test passing fee_rate as a string
        node_2_bal_before = node_2_bal
        node_0_bal_before = node_0_bal
        txid = self.nodes[2].sendmany(amounts={address: 10}, fee_rate=str(fee_rate))
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal_before, node_0_bal_before, Decimal('10'), fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        # Test passing fee_rate as an integer
        amount = Decimal("0.0001")
        node_2_bal_before = node_2_bal
        node_0_bal_before = node_0_bal
        txid = self.nodes[2].sendmany(amounts={address: amount}, fee_rate=fee_rate)
        fee = self.check_pp_fee(self.nodes[2], txid)
        node_2_bal, node_0_bal = self.expected_send_balances(node_2_bal_before, node_0_bal_before, amount, fee, txid, address)
        self.generate(self.nodes[2], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        for key in ["totalFee", "feeRate"]:
            assert_raises_rpc_error(-8, "Unknown named parameter key", self.nodes[2].sendtoaddress, address=address, amount=1, fee_rate=1, key=1)

        # Peercoin uses a fixed minimum fee; lower explicit rates are raised to the floor.
        self.log.info("Test walletcreatefundedpsbt raises low fee_rate to the Peercoin minimum")
        for low_fee_rate in [0, 0.999, 0.000, 0.00000000, "0", "0.000", "0.00000000"]:
            result = self.nodes[2].walletcreatefundedpsbt([], {address: Decimal('10')}, 0, {"fee_rate": low_fee_rate})
            self.check_pp_funded_psbt_fee(result)

        self.log.info("Test sendmany raises if an invalid fee_rate is passed")
        msg = "Invalid amount"
        # Test fee_rate values that don't pass fixed-point parsing checks.
        for invalid_value in ["", 0.000000001, 1e-09, 1.111111111, 1111111111111111, "31.999999999999999999999"]:
            assert_raises_rpc_error(-3, msg, self.nodes[2].sendmany, amounts={address: 1.0}, fee_rate=invalid_value)
        # Test fee_rate values that cannot be represented in sat/vB.
        for invalid_value in [0.0001, 0.00000001, 0.00099999, 31.99999999, "0.0001", "0.00000001", "0.00099999", "31.99999999"]:
            assert_raises_rpc_error(-3, msg, self.nodes[2].sendmany, amounts={address: 10}, fee_rate=invalid_value)
        # Test fee_rate out of range (negative number).
        assert_raises_rpc_error(-3, OUT_OF_RANGE, self.nodes[2].sendmany, amounts={address: 10}, fee_rate=-1)
        # Test type error.
        for invalid_value in [True, {"foo": "bar"}]:
            assert_raises_rpc_error(-3, NOT_A_NUMBER_OR_STRING, self.nodes[2].sendmany, amounts={address: 10}, fee_rate=invalid_value)

        self.log.info("Test sendmany raises if an invalid conf_target or estimate_mode is passed")
        expected_conf_target_msg = "Invalid conf_target, must be between 1 and 1008"
        for target, mode in product([-1, 0, 1009], ["economical", "conservative"]):
            assert_raises_rpc_error(-8, expected_conf_target_msg,
                self.nodes[2].sendmany, amounts={address: 1}, conf_target=target, estimate_mode=mode)
        for target, mode in product([-1, 0], ["btc/kb", "sat/b"]):
            assert_raises_rpc_error(-8, 'Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"',
                self.nodes[2].sendmany, amounts={address: 1}, conf_target=target, estimate_mode=mode)

        self.start_node(3, self.nodes[3].extra_args)
        self.connect_nodes(0, 3)
        self.sync_all()

        # check if we can list zero value tx as available coins
        # 1. create raw_tx
        # 2. hex-changed one output to 0.0
        # 3. sign and send
        # 4. check if recipient (node0) can list the zero value tx
        usp = self.nodes[1].listunspent(query_options={'minimumAmount': str(coinbase_reward)})[0]
        inputs = [{"txid": usp['txid'], "vout": usp['vout']}]
        first_amount = Decimal(str(usp['amount'])) - Decimal('0.02')
        outputs = {self.nodes[1].getnewaddress(): first_amount, self.nodes[0].getnewaddress(): 11.11}

        amount_bytes = int(Decimal('11.11') * 1000000).to_bytes(8, 'little').hex()
        raw_tx = self.nodes[1].createrawtransaction(inputs, outputs).replace(amount_bytes, "0000000000000000")
        signed_raw_tx = self.nodes[1].signrawtransactionwithwallet(raw_tx)
        decoded_raw_tx = self.nodes[1].decoderawtransaction(signed_raw_tx['hex'])
        zero_value_txid = decoded_raw_tx['txid']
        self.nodes[1].sendrawtransaction(signed_raw_tx['hex'])

        self.sync_all()
        self.generate(self.nodes[1], 1)  # mine a block

        unspent_txs = self.nodes[0].listunspent()  # zero value tx must be in listunspents output
        found = False
        for uTx in unspent_txs:
            if uTx['txid'] == zero_value_txid:
                found = True
                assert_equal(uTx['amount'], Decimal('0'))
        assert found

        self.log.info("Test -walletbroadcast")
        self.stop_nodes()
        self.start_node(0, self.node_args_with(0, ["-walletbroadcast=0"]))
        self.start_node(1, self.node_args_with(1, ["-walletbroadcast=0"]))
        self.start_node(2, self.node_args_with(2, ["-walletbroadcast=0"]))
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.sync_all(self.nodes[0:3])

        txid_not_broadcast = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 2)
        tx_obj_not_broadcast = self.nodes[0].gettransaction(txid_not_broadcast)
        self.generate(self.nodes[1], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))  # mine a block, tx should not be in there
        assert_equal(self.nodes[2].getbalance(), node_2_bal)  # should not be changed because tx was not broadcasted

        # now broadcast from another node, mine a block, sync, and check the balance
        self.nodes[1].sendrawtransaction(tx_obj_not_broadcast['hex'])
        self.generate(self.nodes[1], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        node_2_bal += 2
        tx_obj_not_broadcast = self.nodes[0].gettransaction(txid_not_broadcast)
        assert_equal(self.nodes[2].getbalance(), node_2_bal)

        # create another tx
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 2)

        # restart the nodes with -walletbroadcast=1
        self.stop_nodes()
        self.start_node(0)
        self.start_node(1)
        self.start_node(2)
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.sync_blocks(self.nodes[0:3])

        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_blocks(self.nodes[0:3]))
        node_2_bal += 2

        # tx should be added to balance because after restarting the nodes tx should be broadcast
        assert_equal(self.nodes[2].getbalance(), node_2_bal)

        # send a tx with value in a string (PR#6380 +)
        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), "2")
        tx_obj = self.nodes[0].gettransaction(txid)
        assert_equal(tx_obj['amount'], Decimal('-2'))

        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), "0.0001")
        tx_obj = self.nodes[0].gettransaction(txid)
        assert_equal(tx_obj['amount'], Decimal('-0.0001'))

        # check if JSON parser can handle scientific notation in strings
        txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), "1e-4")
        tx_obj = self.nodes[0].gettransaction(txid)
        assert_equal(tx_obj['amount'], Decimal('-0.0001'))

        # General checks for errors from incorrect inputs
        # This will raise an exception because the amount is negative
        assert_raises_rpc_error(-3, OUT_OF_RANGE, self.nodes[0].sendtoaddress, self.nodes[2].getnewaddress(), "-1")

        # This will raise an exception because the amount type is wrong
        assert_raises_rpc_error(-3, "Invalid amount", self.nodes[0].sendtoaddress, self.nodes[2].getnewaddress(), "1f-4")

        # This will raise an exception since generate does not accept a string
        assert_raises_rpc_error(-3, "not of expected type number", self.generate, self.nodes[0], "2")

        if not self.options.descriptors:

            # This will raise an exception for the invalid private key format
            assert_raises_rpc_error(-5, "Invalid private key encoding", self.nodes[0].importprivkey, "invalid")

            # This will raise an exception for importing an address with the PS2H flag
            temp_address = self.nodes[1].getnewaddress("", "p2sh-segwit")
            assert_raises_rpc_error(-5, "Cannot use the p2sh flag with an address - use a script instead", self.nodes[0].importaddress, temp_address, "label", False, True)

            # This will raise an exception for attempting to dump the private key of an address you do not own
            assert_raises_rpc_error(-3, "Address does not refer to a key", self.nodes[0].dumpprivkey, temp_address)

            # This will raise an exception for attempting to get the private key of an invalid Bitcoin address
            assert_raises_rpc_error(-5, "Invalid Bitcoin address", self.nodes[0].dumpprivkey, "invalid")

            # This will raise an exception for attempting to set a label for an invalid Bitcoin address
            assert_raises_rpc_error(-5, "Invalid Bitcoin address", self.nodes[0].setlabel, "invalid address", "label")

            # This will raise an exception for importing an invalid address
            assert_raises_rpc_error(-5, "Invalid Bitcoin address or script", self.nodes[0].importaddress, "invalid")

            # This will raise an exception for attempting to import a pubkey that isn't in hex
            assert_raises_rpc_error(-5, "Pubkey must be a hex string", self.nodes[0].importpubkey, "not hex")

            # This will raise an exception for importing an invalid pubkey
            assert_raises_rpc_error(-5, "Pubkey is not a valid public key", self.nodes[0].importpubkey, "5361746f736869204e616b616d6f746f")

            # Bech32m addresses cannot be imported into a legacy wallet
            assert_raises_rpc_error(-5, "Bech32m addresses cannot be imported into legacy wallets", self.nodes[0].importaddress, "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6")

            # Import address and private key to check correct behavior of spendable unspents
            # 1. Send some coins to generate new UTXO
            address_to_import = self.nodes[2].getnewaddress()
            txid = self.nodes[0].sendtoaddress(address_to_import, 1)
            self.sync_mempools(self.nodes[0:3])
            vout = find_vout_for_address(self.nodes[2], txid, address_to_import)
            self.nodes[2].lockunspent(False, [{"txid": txid, "vout": vout}])
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))

            self.log.info("Test sendtoaddress with fee_rate param (explicit fee rate in sat/vB)")
            prebalance = self.nodes[2].getbalance()
            assert prebalance > 2
            address = self.nodes[1].getnewaddress()
            amount = 3
            fee_rate_sat_vb = 2
            fee_rate_btc_kvb = fee_rate_sat_vb * 1e3 / 1e8
            # Test passing fee_rate as an integer
            txid = self.nodes[2].sendtoaddress(address=address, amount=amount, fee_rate=fee_rate_sat_vb)
            tx_size = self.get_vsize(self.nodes[2].gettransaction(txid)['hex'])
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
            postbalance = self.nodes[2].getbalance()
            fee = prebalance - postbalance - Decimal(amount)
            assert_fee_amount(fee, tx_size, Decimal(fee_rate_btc_kvb))

            prebalance = self.nodes[2].getbalance()
            amount = Decimal("0.001")
            fee_rate_sat_vb = 1.23
            fee_rate_btc_kvb = fee_rate_sat_vb * 1e3 / 1e8
            # Test passing fee_rate as a string
            txid = self.nodes[2].sendtoaddress(address=address, amount=amount, fee_rate=str(fee_rate_sat_vb))
            tx_size = self.get_vsize(self.nodes[2].gettransaction(txid)['hex'])
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
            postbalance = self.nodes[2].getbalance()
            fee = prebalance - postbalance - amount
            assert_fee_amount(fee, tx_size, Decimal(fee_rate_btc_kvb))

            for key in ["totalFee", "feeRate"]:
                assert_raises_rpc_error(-8, "Unknown named parameter key", self.nodes[2].sendtoaddress, address=address, amount=1, fee_rate=1, key=1)

            # Test setting explicit fee rate just below the minimum.
            self.log.info("Test sendtoaddress raises 'fee rate too low' if fee_rate of 0.99999999 is passed")
            assert_raises_rpc_error(-6, "Fee rate (0.999 sat/vB) is lower than the minimum fee rate setting (1.000 sat/vB)",
                self.nodes[2].sendtoaddress, address=address, amount=1, fee_rate=0.999)

            self.log.info("Test sendtoaddress raises if an invalid fee_rate is passed")
            # Test fee_rate with zero values.
            msg = "Fee rate (0.000 sat/vB) is lower than the minimum fee rate setting (1.000 sat/vB)"
            for zero_value in [0, 0.000, 0.00000000, "0", "0.000", "0.00000000"]:
                assert_raises_rpc_error(-6, msg, self.nodes[2].sendtoaddress, address=address, amount=1, fee_rate=zero_value)
            msg = "Invalid amount"
            # Test fee_rate values that don't pass fixed-point parsing checks.
            for invalid_value in ["", 0.000000001, 1e-09, 1.111111111, 1111111111111111, "31.999999999999999999999"]:
                assert_raises_rpc_error(-3, msg, self.nodes[2].sendtoaddress, address=address, amount=1.0, fee_rate=invalid_value)
            # Test fee_rate values that cannot be represented in sat/vB.
            for invalid_value in [0.0001, 0.00000001, 0.00099999, 31.99999999, "0.0001", "0.00000001", "0.00099999", "31.99999999"]:
                assert_raises_rpc_error(-3, msg, self.nodes[2].sendtoaddress, address=address, amount=10, fee_rate=invalid_value)
            # Test fee_rate out of range (negative number).
            assert_raises_rpc_error(-3, OUT_OF_RANGE, self.nodes[2].sendtoaddress, address=address, amount=1.0, fee_rate=-1)
            # Test type error.
            for invalid_value in [True, {"foo": "bar"}]:
                assert_raises_rpc_error(-3, NOT_A_NUMBER_OR_STRING, self.nodes[2].sendtoaddress, address=address, amount=1.0, fee_rate=invalid_value)

            self.log.info("Test sendtoaddress raises if an invalid conf_target or estimate_mode is passed")
            for target, mode in product([-1, 0, 1009], ["economical", "conservative"]):
                assert_raises_rpc_error(-8, "Invalid conf_target, must be between 1 and 1008",  # max value of 1008 per src/policy/fees.h
                    self.nodes[2].sendtoaddress, address=address, amount=1, conf_target=target, estimate_mode=mode)
            for target, mode in product([-1, 0], ["btc/kb", "sat/b"]):
                assert_raises_rpc_error(-8, 'Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"',
                    self.nodes[2].sendtoaddress, address=address, amount=1, conf_target=target, estimate_mode=mode)

            # Test setting explicit fee rate just below the minimum.
            self.log.info("Test sendtoaddress raises 'fee rate too low' if fee_rate of 0.99999999 is passed")
            assert_raises_rpc_error(-6, "Fee rate (0.00000999 BTC/kB) is lower than the minimum fee rate setting (0.00001000 BTC/kB)",
                self.nodes[2].sendtoaddress, address=address, amount=1, fee_rate=0.99999999)

            self.log.info("Test sendtoaddress raises if fee_rate of 0 or -1 is passed")
            assert_raises_rpc_error(-6, "Fee rate (0.000 sat/vB) is lower than the minimum fee rate setting (1.000 sat/vB)",
                self.nodes[2].sendtoaddress, address=address, amount=10, fee_rate=0)
            assert_raises_rpc_error(-3, OUT_OF_RANGE, self.nodes[2].sendtoaddress, address=address, amount=1.0, fee_rate=-1)

            self.log.info("Test sendtoaddress raises if an invalid conf_target or estimate_mode is passed")
            for target, mode in product([-1, 0, 1009], ["economical", "conservative"]):
                assert_raises_rpc_error(-8, "Invalid conf_target, must be between 1 and 1008",  # max value of 1008 per src/policy/fees.h
                    self.nodes[2].sendtoaddress, address=address, amount=1, conf_target=target, estimate_mode=mode)
            for target, mode in product([-1, 0], ["btc/kb", "sat/b"]):
                assert_raises_rpc_error(-8, 'Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"',
                    self.nodes[2].sendtoaddress, address=address, amount=1, conf_target=target, estimate_mode=mode)

            # 2. Import address from node2 to node1
            self.nodes[1].importaddress(address_to_import)

            # 3. Validate that the imported address is watch-only on node1
            assert self.nodes[1].getaddressinfo(address_to_import)["iswatchonly"]

            # 4. Check that the unspents after import are not spendable
            assert_array_result(self.nodes[1].listunspent(),
                                {"address": address_to_import},
                                {"spendable": False})

            # 5. Import private key of the previously imported address on node1
            priv_key = self.nodes[2].dumpprivkey(address_to_import)
            self.nodes[1].importprivkey(priv_key)

            # 6. Check that the unspents are now spendable on node1
            assert_array_result(self.nodes[1].listunspent(),
                                {"address": address_to_import},
                                {"spendable": True})

        # Mine a block from node0 to an address from node1
        coinbase_addr = self.nodes[1].getnewaddress()
        block_hash = self.generatetoaddress(self.nodes[0], 1, coinbase_addr, sync_fun=lambda: self.sync_all(self.nodes[0:3]))[0]
        coinbase_txid = self.nodes[0].getblock(block_hash)['tx'][0]

        # Check that the txid and balance is found by node1
        self.nodes[1].gettransaction(coinbase_txid)

        # check if wallet or blockchain maintenance changes the balance
        self.sync_all(self.nodes[0:3])
        blocks = self.generate(self.nodes[0], 2, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        balance_nodes = [self.nodes[i].getbalance() for i in range(3)]
        block_count = self.nodes[0].getblockcount()

        # Check modes:
        #   - True: unicode escaped as \u....
        #   - False: unicode directly as UTF-8
        for mode in [True, False]:
            self.nodes[0].rpc.ensure_ascii = mode
            # unicode check: Basic Multilingual Plane, Supplementary Plane respectively
            for label in [u'рыба', u'𝅘𝅥𝅯']:
                addr = self.nodes[0].getnewaddress()
                self.nodes[0].setlabel(addr, label)
                test_address(self.nodes[0], addr, labels=[label])
                assert label in self.nodes[0].listlabels()
        self.nodes[0].rpc.ensure_ascii = True  # restore to default

        # -reindex tests
        chainlimit = 6
        self.log.info("Test -reindex")
        self.stop_nodes()
        # set lower ancestor limit for later
        self.start_node(0, self.node_args_with(0, ['-reindex', "-walletrejectlongchains=0", "-limitancestorcount=" + str(chainlimit)]))
        self.start_node(1, self.node_args_with(1, ['-reindex', "-limitancestorcount=" + str(chainlimit)]))
        self.start_node(2, self.node_args_with(2, ['-reindex', "-limitancestorcount=" + str(chainlimit)]))
        # reindex will leave rpc warm up "early"; Wait for it to finish
        self.wait_until(lambda: [block_count] * 3 == [self.nodes[i].getblockcount() for i in range(3)])
        assert_equal(balance_nodes, [self.nodes[i].getbalance() for i in range(3)])

        # Exercise listsinceblock with the last two blocks
        coinbase_tx_1 = self.nodes[0].listsinceblock(blocks[0])
        assert_equal(coinbase_tx_1["lastblock"], blocks[1])
        assert_equal(len(coinbase_tx_1["transactions"]), 1)
        assert_equal(coinbase_tx_1["transactions"][0]["blockhash"], blocks[1])
        assert_equal(len(self.nodes[0].listsinceblock(blocks[1])["transactions"]), 0)

        # Bitcoin mempool-chain tests are skipped because Peercoin does not support transaction replacement.
        # PP fixed fees use the outgoing amount as the fee when fees from inputs are too small.

        # Test getaddressinfo on external address. Note that these addresses are taken from disablewallet.py
        assert_raises_rpc_error(-5, "Invalid or unsupported Base58-encoded address.", self.nodes[0].getaddressinfo, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        address_info = self.nodes[0].getaddressinfo("mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ")
        assert_equal(address_info['address'], "mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ")
        assert_equal(address_info["scriptPubKey"], "76a9144e3854046c7bd1594ac904e4793b6a45b36dea0988ac")
        assert not address_info["ismine"]
        assert not address_info["iswatchonly"]
        assert not address_info["isscript"]
        assert not address_info["ischange"]

        # Test getaddressinfo 'ischange' field on change address.
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        destination = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress(destination, 0.123)
        tx = self.nodes[0].gettransaction(txid=txid, verbose=True)['decoded']
        output_addresses = [vout['scriptPubKey']['address'] for vout in tx["vout"]]
        assert len(output_addresses) > 1
        for address in output_addresses:
            ischange = self.nodes[0].getaddressinfo(address)['ischange']
            assert_equal(ischange, address != destination)
            if ischange:
                change = address
        self.nodes[0].setlabel(change, 'foobar')
        assert_equal(self.nodes[0].getaddressinfo(change)['ischange'], False)

        # Test gettransaction response with different arguments.
        self.log.info("Testing gettransaction response with different arguments...")
        self.nodes[0].setlabel(change, 'baz')
        baz = self.nodes[0].listtransactions(label="baz", count=1)[0]
        expected_receive_vout = {"label":    "baz",
                                 "address":  baz["address"],
                                 "amount":   baz["amount"],
                                 "category": baz["category"],
                                 "vout":     baz["vout"]}
        expected_fields = frozenset({'amount', 'bip125-replaceable', 'confirmations', 'details', 'fee',
                                     'hex', 'time', 'timereceived', 'trusted', 'txid', 'wtxid', 'walletconflicts',
                                     'mempoolconflicts', 'lastprocessedblock'})
        verbose_field = "decoded"
        expected_verbose_fields = expected_fields | {verbose_field}

        self.log.debug("Testing gettransaction response without verbose")
        tx = self.nodes[0].gettransaction(txid=txid)
        assert_equal(set([*tx]), expected_fields)
        assert_array_result(tx["details"], {"category": "receive"}, expected_receive_vout)

        self.log.debug("Testing gettransaction response with verbose set to False")
        tx = self.nodes[0].gettransaction(txid=txid, verbose=False)
        assert_equal(set([*tx]), expected_fields)
        assert_array_result(tx["details"], {"category": "receive"}, expected_receive_vout)

        self.log.debug("Testing gettransaction response with verbose set to True")
        tx = self.nodes[0].gettransaction(txid=txid, verbose=True)
        assert_equal(set([*tx]), expected_verbose_fields)
        assert_array_result(tx["details"], {"category": "receive"}, expected_receive_vout)
        assert_equal(tx[verbose_field], self.nodes[0].decoderawtransaction(tx["hex"]))

        self.log.info("Test send* RPCs with verbose=True")
        address = self.nodes[0].getnewaddress("test")
        txid_feeReason_one = self.nodes[2].sendtoaddress(address=address, amount=5, verbose=True)
        self.check_pp_fee(self.nodes[2], txid_feeReason_one['txid'])
        txid_feeReason_two = self.nodes[2].sendmany(dummy='', amounts={address: 5}, verbose=True)
        self.check_pp_fee(self.nodes[2], txid_feeReason_two['txid'])
        self.log.info("Test send* RPCs with verbose=False")
        txid_feeReason_three = self.nodes[2].sendtoaddress(address=address, amount=5, verbose=False)
        assert_equal(self.nodes[2].gettransaction(txid_feeReason_three)['txid'], txid_feeReason_three)
        txid_feeReason_four = self.nodes[2].sendmany(dummy='', amounts={address: 5}, verbose=False)
        assert_equal(self.nodes[2].gettransaction(txid_feeReason_four)['txid'], txid_feeReason_four)

        if self.options.descriptors:
            self.log.info("Testing 'listunspent' outputs the parent descriptor(s) of coins")
            # Create two multisig descriptors, and send a UTxO each.
            multi_a = descsum_create("wsh(multi(1,tpubD6NzVbkrYhZ4YBNjUo96Jxd1u4XKWgnoc7LsA1jz3Yc2NiDbhtfBhaBtemB73n9V5vtJHwU6FVXwggTbeoJWQ1rzdz8ysDuQkpnaHyvnvzR/*,tpubD6NzVbkrYhZ4YHdDGMAYGaWxMSC1B6tPRTHuU5t3BcfcS3nrF523iFm5waFd1pP3ZvJt4Jr8XmCmsTBNx5suhcSgtzpGjGMASR3tau1hJz4/*))")
            multi_b = descsum_create("wsh(multi(1,tpubD6NzVbkrYhZ4YHdDGMAYGaWxMSC1B6tPRTHuU5t3BcfcS3nrF523iFm5waFd1pP3ZvJt4Jr8XmCmsTBNx5suhcSgtzpGjGMASR3tau1hJz4/*,tpubD6NzVbkrYhZ4Y2RLiuEzNQkntjmsLpPYDm3LTRBYynUQtDtpzeUKAcb9sYthSFL3YR74cdFgF5mW8yKxv2W2CWuZDFR2dUpE5PF9kbrVXNZ/*))")
            addr_a = self.nodes[0].deriveaddresses(multi_a, 0)[0]
            addr_b = self.nodes[0].deriveaddresses(multi_b, 0)[0]
            txid_a = self.nodes[0].sendtoaddress(addr_a, 0.01)
            txid_b = self.nodes[0].sendtoaddress(addr_b, 0.01)
            self.generate(self.nodes[0], 1, sync_fun=self.no_op)
            # Now import the descriptors, make sure we can identify on which descriptor each coin was received.
            self.nodes[0].createwallet(wallet_name="wo", descriptors=True, disable_private_keys=True)
            wo_wallet = self.nodes[0].get_wallet_rpc("wo")
            wo_wallet.importdescriptors([
                {
                    "desc": multi_a,
                    "active": False,
                    "timestamp": "now",
                },
                {
                    "desc": multi_b,
                    "active": False,
                    "timestamp": "now",
                },
            ])
            coins = wo_wallet.listunspent(minconf=0)
            assert_equal(len(coins), 2)
            coin_a = next(c for c in coins if c["txid"] == txid_a)
            assert_equal(coin_a["parent_descs"][0], multi_a)
            coin_b = next(c for c in coins if c["txid"] == txid_b)
            assert_equal(coin_b["parent_descs"][0], multi_b)
            self.nodes[0].unloadwallet("wo")

        # Bitcoin zeroconf-change tests are skipped because Peercoin's wallet tx construction and fee model differ.
        self.log.info("Skipping Bitcoin-specific spendzeroconfchange test")


if __name__ == '__main__':
    WalletTest().main()
