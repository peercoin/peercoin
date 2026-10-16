#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    get_fee,
)
from test_framework.wallet import (
    COIN,
    DEFAULT_FEE,
    MiniWallet,
)
from test_framework.blocktools import (
    create_empty_fork,
)

TRUC_MAX_VSIZE = 10000
TRUC_CHILD_MAX_VSIZE = 1000

def cleanup(extra_args=None):
    def decorator(func):
        def wrapper(self):
            try:
                if extra_args is not None:
                    self.restart_node(0, extra_args=extra_args)
                func(self)
            finally:
                # Clear mempool again after test
                self.generate(self.nodes[0], 1)
                if extra_args is not None:
                    self.restart_node(0)
        return wrapper
    return decorator

class MempoolTRUC(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[]]
        self.setup_clean_chain = True

    def check_mempool(self, txids):
        """Assert exact contents of the node's mempool (by txid)."""
        mempool_contents = self.nodes[0].getrawmempool()
        assert_equal(len(txids), len(mempool_contents))
        assert all([txid in txids for txid in mempool_contents])

    def trigger_reorg(self, fork_blocks):
        """Trigger reorg of the fork blocks."""
        for block in fork_blocks:
            self.nodes[0].submitblock(block.serialize().hex())
        assert_equal(self.nodes[0].getbestblockhash(), fork_blocks[-1].hash_hex)

    @cleanup()
    def test_truc_max_vsize(self):
        node = self.nodes[0]
        self.log.info("Test TRUC-specific maximum transaction vsize")
        tx_v3_heavy = self.wallet.create_self_transfer(target_vsize=TRUC_MAX_VSIZE + 1, version=3)
        assert_greater_than_or_equal(tx_v3_heavy["tx"].get_vsize(), TRUC_MAX_VSIZE)
        expected_error_heavy = f"TRUC-violation, version=3 tx {tx_v3_heavy['txid']} (wtxid={tx_v3_heavy['wtxid']}) is too big"
        assert_raises_rpc_error(-26, expected_error_heavy, node.sendrawtransaction, tx_v3_heavy["hex"])
        self.check_mempool([])

        # Ensure we are hitting the TRUC-specific limit and not something else
        tx_v2_heavy = self.wallet.send_self_transfer(from_node=node, target_vsize=TRUC_MAX_VSIZE + 1, version=2)
        self.check_mempool([tx_v2_heavy["txid"]])

    @cleanup()
    def test_truc_acceptance(self):
        node = self.nodes[0]
        self.log.info("Test a child of a TRUC transaction cannot be more than 1000vB")
        tx_v3_parent_normal = self.wallet.send_self_transfer(from_node=node, version=3)
        self.check_mempool([tx_v3_parent_normal["txid"]])
        tx_v3_child_heavy = self.wallet.create_self_transfer(
            utxo_to_spend=tx_v3_parent_normal["new_utxo"],
            target_vsize=TRUC_CHILD_MAX_VSIZE + 1,
            version=3
        )
        assert_greater_than_or_equal(tx_v3_child_heavy["tx"].get_vsize(), TRUC_CHILD_MAX_VSIZE)
        expected_error_child_heavy = f"TRUC-violation, version=3 child tx {tx_v3_child_heavy['txid']} (wtxid={tx_v3_child_heavy['wtxid']}) is too big"
        assert_raises_rpc_error(-26, expected_error_child_heavy, node.sendrawtransaction, tx_v3_child_heavy["hex"])
        self.check_mempool([tx_v3_parent_normal["txid"]])
        # tx has no descendants
        assert_equal(node.getmempoolentry(tx_v3_parent_normal["txid"])["descendantcount"], 1)

        self.log.info("Test a child within the TRUC size limit is accepted")
        tx_v3_child_almost_heavy = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=tx_v3_parent_normal["new_utxo"],
            target_vsize=TRUC_CHILD_MAX_VSIZE - 3,
            version=3
        )
        assert_greater_than_or_equal(TRUC_CHILD_MAX_VSIZE, tx_v3_child_almost_heavy["tx"].get_vsize())
        self.check_mempool([tx_v3_parent_normal["txid"], tx_v3_child_almost_heavy["txid"]])
        assert_equal(node.getmempoolentry(tx_v3_parent_normal["txid"])["descendantcount"], 2)


    @cleanup()
    def test_truc_reorg(self):
        node = self.nodes[0]

        # Prep for fork
        fork_blocks = create_empty_fork(node)
        self.log.info("Test that, during a reorg, TRUC rules are not enforced")
        self.check_mempool([])

        # Testing 2<-3 versions allowed
        tx_v2_block = self.wallet.create_self_transfer(version=2)

        # Testing 3<-2 versions allowed
        tx_v3_block = self.wallet.create_self_transfer(version=3)

        # Testing overly-large child size
        tx_v3_block2 = self.wallet.create_self_transfer(version=3)

        # Also create a linear chain of 3 TRUC transactions that will be directly mined, followed by one v2 in-mempool after block is made
        tx_chain_1 = self.wallet.create_self_transfer(version=3)
        tx_chain_2 = self.wallet.create_self_transfer(utxo_to_spend=tx_chain_1["new_utxo"], version=3)
        tx_chain_3 = self.wallet.create_self_transfer(utxo_to_spend=tx_chain_2["new_utxo"], version=3)

        tx_to_mine = [tx_v3_block["hex"], tx_v2_block["hex"], tx_v3_block2["hex"], tx_chain_1["hex"], tx_chain_2["hex"], tx_chain_3["hex"]]
        self.generateblock(node, output="raw(42)", transactions=tx_to_mine)

        self.check_mempool([])

        tx_v2_from_v3 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v3_block["new_utxo"], version=2)
        tx_v3_from_v2 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v2_block["new_utxo"], version=3)
        tx_v3_child_large = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v3_block2["new_utxo"], target_vsize=1250, version=3)
        assert_greater_than(node.getmempoolentry(tx_v3_child_large["txid"])["vsize"], TRUC_CHILD_MAX_VSIZE)
        tx_chain_4 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_chain_3["new_utxo"], version=2)
        self.check_mempool([tx_v2_from_v3["txid"], tx_v3_from_v2["txid"], tx_v3_child_large["txid"], tx_chain_4["txid"]])

        # Reorg should have all block transactions re-accepted, ignoring TRUC enforcement
        self.trigger_reorg(fork_blocks)
        self.check_mempool([tx_v3_block["txid"], tx_v2_block["txid"], tx_v3_block2["txid"], tx_v2_from_v3["txid"], tx_v3_from_v2["txid"], tx_v3_child_large["txid"], tx_chain_1["txid"], tx_chain_2["txid"], tx_chain_3["txid"], tx_chain_4["txid"]])

    @cleanup(extra_args=["-limitclustercount=1"])
    def test_nondefault_package_limits(self):
        """
        Max standard tx size + TRUC rules imply the cluster rules (at their default
        values), but those checks must not be skipped. Ensure both sets of checks are done by
        changing the cluster limit configurations.
        """
        node = self.nodes[0]
        self.log.info("Test that a decreased cluster count limit also applies to TRUC child")
        parent_target_vsize = 9990
        child_target_vsize = 500
        tx_v3_parent_large1 = self.wallet.send_self_transfer(
            from_node=node,
            target_vsize=parent_target_vsize,
            version=3
        )
        tx_v3_child_large1 = self.wallet.create_self_transfer(
            utxo_to_spend=tx_v3_parent_large1["new_utxo"],
            target_vsize=child_target_vsize,
            version=3
        )

        # Parent and child are within v3 limits, but cluster count limit is exceeded.
        assert_greater_than_or_equal(TRUC_MAX_VSIZE, tx_v3_parent_large1["tx"].get_vsize())
        assert_greater_than_or_equal(TRUC_CHILD_MAX_VSIZE, tx_v3_child_large1["tx"].get_vsize())

        assert_raises_rpc_error(-26, "too-large-cluster", node.sendrawtransaction, tx_v3_child_large1["hex"])
        self.check_mempool([tx_v3_parent_large1["txid"]])
        assert_equal(node.getmempoolentry(tx_v3_parent_large1["txid"])["descendantcount"], 1)
        self.generate(node, 1)

        self.log.info("Test that a decreased limitclustersize also applies to TRUC child")
        self.restart_node(0, extra_args=["-limitclustersize=10", "-acceptnonstdtxn=1"])
        tx_v3_parent_large2 = self.wallet.send_self_transfer(from_node=node, target_vsize=parent_target_vsize, version=3)
        tx_v3_child_large2 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_parent_large2["new_utxo"], target_vsize=child_target_vsize, version=3)
        # Parent and child are within TRUC limits
        assert_greater_than_or_equal(TRUC_MAX_VSIZE, tx_v3_parent_large2["tx"].get_vsize())
        assert_greater_than_or_equal(TRUC_CHILD_MAX_VSIZE, tx_v3_child_large2["tx"].get_vsize())
        assert_raises_rpc_error(-26, "too-large-cluster", node.sendrawtransaction, tx_v3_child_large2["hex"])
        self.log.info("Test that a decreased limitclustercount also applies to TRUC transactions")
        self.restart_node(0, extra_args=["-limitclustercount=1", "-acceptnonstdtxn=1"])
        assert_raises_rpc_error(-26, "too-large-cluster", node.sendrawtransaction, tx_v3_child_large2["hex"])
        self.check_mempool([tx_v3_parent_large2["txid"]])

    @cleanup()
    def test_truc_ancestors_package(self):
        self.log.info("Test that TRUC ancestor limits are checked within the package")
        node = self.nodes[0]
        tx_v3_parent_normal = self.wallet.create_self_transfer(
            fee_rate=0,
            target_vsize=1001,
            version=3
        )
        tx_v3_parent_2_normal = self.wallet.create_self_transfer(
            fee_rate=0,
            target_vsize=1001,
            version=3
        )
        tx_v3_child_multiparent = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[tx_v3_parent_normal["new_utxo"], tx_v3_parent_2_normal["new_utxo"]],
            fee_per_output=10000,
            version=3
        )
        tx_v3_child_heavy = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[tx_v3_parent_normal["new_utxo"]],
            target_vsize=TRUC_CHILD_MAX_VSIZE + 1,
            fee_per_output=10000,
            version=3
        )

        self.check_mempool([])
        result = node.submitpackage([tx_v3_parent_normal["hex"], tx_v3_parent_2_normal["hex"], tx_v3_child_multiparent["hex"]])
        assert_equal(result['package_msg'], f"TRUC-violation, tx {tx_v3_child_multiparent['txid']} (wtxid={tx_v3_child_multiparent['wtxid']}) would have too many ancestors")
        self.check_mempool([])

        self.check_mempool([])
        result = node.submitpackage([tx_v3_parent_normal["hex"], tx_v3_child_heavy["hex"]])
        # tx_v3_child_heavy is heavy based on vsize, not sigops.
        assert_equal(result['package_msg'], f"TRUC-violation, version=3 child tx {tx_v3_child_heavy['txid']} (wtxid={tx_v3_child_heavy['wtxid']}) is too big: {tx_v3_child_heavy['tx'].get_vsize()} > 1000 virtual bytes")
        self.check_mempool([])

        tx_v3_parent = self.wallet.create_self_transfer(version=3)
        tx_v3_child = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_parent["new_utxo"], version=3)
        tx_v3_grandchild = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_child["new_utxo"], version=3)
        result = node.testmempoolaccept([tx_v3_parent["hex"], tx_v3_child["hex"], tx_v3_grandchild["hex"]])
        assert all([txresult["package-error"] == f"TRUC-violation, tx {tx_v3_grandchild['txid']} (wtxid={tx_v3_grandchild['wtxid']}) would have too many ancestors" for txresult in result])

    @cleanup(extra_args=None)
    def test_truc_ancestors_package_and_mempool(self):
        """
        A TRUC transaction in a package cannot have 2 TRUC parents.
        Test that if we have a transaction graph A -> B -> C, where A, B, C are
        all TRUC transactions, that we cannot use submitpackage to get the
        transactions all into the mempool.

        Verify, in particular, that if A is already in the mempool, then
        submitpackage(B, C) will fail.
        """
        node = self.nodes[0]
        self.log.info("Test that TRUC ancestor limits include transactions within the package and all in-mempool ancestors")
        # This is our transaction "A":
        tx_in_mempool = self.wallet.send_self_transfer(from_node=node, version=3)

        # Verify that A is in the mempool
        self.check_mempool([tx_in_mempool["txid"]])

        # tx_0fee_parent is our transaction "B"; just create it.
        tx_0fee_parent = self.wallet.create_self_transfer(utxo_to_spend=tx_in_mempool["new_utxo"], fee=0, fee_rate=0, version=3)

        # tx_child_violator is our transaction "C"; create it:
        tx_child_violator = self.wallet.create_self_transfer_multi(utxos_to_spend=[tx_0fee_parent["new_utxo"]], version=3)

        # submitpackage(B, C) should fail
        result = node.submitpackage([tx_0fee_parent["hex"], tx_child_violator["hex"]])
        assert_equal(result['package_msg'], f"TRUC-violation, tx {tx_child_violator['txid']} (wtxid={tx_child_violator['wtxid']}) would have too many ancestors")
        self.check_mempool([tx_in_mempool["txid"]])


    @cleanup()
    def test_truc_package_inheritance(self):
        self.log.info("Test that TRUC inheritance is checked within package")
        node = self.nodes[0]
        tx_v3_parent = self.wallet.create_self_transfer(
            fee_rate=0,
            target_vsize=1001,
            version=3
        )
        tx_v2_child = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[tx_v3_parent["new_utxo"]],
            fee_per_output=10000,
            version=2
        )
        self.check_mempool([])
        result = node.submitpackage([tx_v3_parent["hex"], tx_v2_child["hex"]])
        assert_equal(result['package_msg'], f"TRUC-violation, non-version=3 tx {tx_v2_child['txid']} (wtxid={tx_v2_child['wtxid']}) cannot spend from version=3 tx {tx_v3_parent['txid']} (wtxid={tx_v3_parent['wtxid']})")
        self.check_mempool([])

    @cleanup(extra_args=None)
    def test_truc_in_testmempoolaccept(self):
        node = self.nodes[0]

        self.log.info("Test that TRUC inheritance is accurately assessed in testmempoolaccept")
        tx_v2 = self.wallet.create_self_transfer(version=2)
        tx_v2_from_v2 = self.wallet.create_self_transfer(utxo_to_spend=tx_v2["new_utxo"], version=2)
        tx_v3_from_v2 = self.wallet.create_self_transfer(utxo_to_spend=tx_v2["new_utxo"], version=3)
        tx_v3 = self.wallet.create_self_transfer(version=3)
        tx_v2_from_v3 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3["new_utxo"], version=2)
        tx_v3_from_v3 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3["new_utxo"], version=3)

        # testmempoolaccept paths don't require child-with-parents topology. Ensure that topology
        # assumptions aren't made in inheritance checks.
        test_accept_v2_and_v3 = node.testmempoolaccept([tx_v2["hex"], tx_v3["hex"]])
        assert all([result["allowed"] for result in test_accept_v2_and_v3])

        test_accept_v3_from_v2 = node.testmempoolaccept([tx_v2["hex"], tx_v3_from_v2["hex"]])
        expected_error_v3_from_v2 = f"TRUC-violation, version=3 tx {tx_v3_from_v2['txid']} (wtxid={tx_v3_from_v2['wtxid']}) cannot spend from non-version=3 tx {tx_v2['txid']} (wtxid={tx_v2['wtxid']})"
        assert all([result["package-error"] == expected_error_v3_from_v2 for result in test_accept_v3_from_v2])

        test_accept_v2_from_v3 = node.testmempoolaccept([tx_v3["hex"], tx_v2_from_v3["hex"]])
        expected_error_v2_from_v3 = f"TRUC-violation, non-version=3 tx {tx_v2_from_v3['txid']} (wtxid={tx_v2_from_v3['wtxid']}) cannot spend from version=3 tx {tx_v3['txid']} (wtxid={tx_v3['wtxid']})"
        assert all([result["package-error"] == expected_error_v2_from_v3 for result in test_accept_v2_from_v3])

        test_accept_pairs = node.testmempoolaccept([tx_v2["hex"], tx_v3["hex"], tx_v2_from_v2["hex"], tx_v3_from_v3["hex"]])
        assert all([result["allowed"] for result in test_accept_pairs])

        self.log.info("Test that descendant violations are caught in testmempoolaccept")
        tx_v3_independent = self.wallet.create_self_transfer(version=3)
        tx_v3_parent = self.wallet.create_self_transfer_multi(num_outputs=2, version=3)
        tx_v3_child_1 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_parent["new_utxos"][0], version=3)
        tx_v3_child_2 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_parent["new_utxos"][1], version=3)
        test_accept_2children = node.testmempoolaccept([tx_v3_parent["hex"], tx_v3_child_1["hex"], tx_v3_child_2["hex"]])
        expected_error_2children = f"TRUC-violation, tx {tx_v3_parent['txid']} (wtxid={tx_v3_parent['wtxid']}) would exceed descendant count limit"
        assert all([result["package-error"] == expected_error_2children for result in test_accept_2children])

        # Extra TRUC transaction does not get incorrectly marked as extra descendant
        test_accept_1child_with_exra = node.testmempoolaccept([tx_v3_parent["hex"], tx_v3_child_1["hex"], tx_v3_independent["hex"]])
        assert all([result["allowed"] for result in test_accept_1child_with_exra])

        # Extra TRUC transaction does not make us ignore the extra descendant
        test_accept_2children_with_exra = node.testmempoolaccept([tx_v3_parent["hex"], tx_v3_child_1["hex"], tx_v3_child_2["hex"], tx_v3_independent["hex"]])
        expected_error_extra = f"TRUC-violation, tx {tx_v3_parent['txid']} (wtxid={tx_v3_parent['wtxid']}) would exceed descendant count limit"
        assert all([result["package-error"] == expected_error_extra for result in test_accept_2children_with_exra])
        # Same result if the parent is already in mempool
        node.sendrawtransaction(tx_v3_parent["hex"])
        test_accept_2children_with_in_mempool_parent = node.testmempoolaccept([tx_v3_child_1["hex"], tx_v3_child_2["hex"]])
        assert all([result["package-error"] == expected_error_extra for result in test_accept_2children_with_in_mempool_parent])


    @cleanup(extra_args=None)
    def test_minrelay_in_package_combos(self):
        node = self.nodes[0]
        self.log.info("Test that all transaction versions can be under minrelaytxfee for various settings...")

        for minrelay_setting in (0, 5, 10, 100, 500, 1000, 5000, 333333, 2500000):
            self.log.info(f"-> Test -minrelaytxfee={minrelay_setting}sat/kvB...")
            setting_decimal = minrelay_setting / Decimal(COIN)
            self.restart_node(0, extra_args=[f"-minrelaytxfee={setting_decimal:.8f}", "-persistmempool=0"])
            minrelayfeerate = node.getmempoolinfo()["minrelaytxfee"]
            high_feerate = minrelayfeerate * 50

            tx_v3_0fee_parent = self.wallet.create_self_transfer(fee=0, fee_rate=0, confirmed_only=True, version=3)
            tx_v3_child = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_0fee_parent["new_utxo"], fee_rate=high_feerate, version=3)
            total_v3_fee = tx_v3_child["fee"] + tx_v3_0fee_parent["fee"]
            total_v3_size = tx_v3_child["tx"].get_vsize() + tx_v3_0fee_parent["tx"].get_vsize()
            assert_greater_than_or_equal(total_v3_fee, get_fee(total_v3_size, minrelayfeerate))
            if minrelayfeerate > 0:
                assert_greater_than(get_fee(tx_v3_0fee_parent["tx"].get_vsize(), minrelayfeerate), 0)
                # Always need to pay at least 1 satoshi for entry, even if minimum feerate is very low
                assert_greater_than(total_v3_fee, 0)
                # Also create a version where the child is at minrelaytxfee
                tx_v3_child_minrelay = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_0fee_parent["new_utxo"], fee_rate=minrelayfeerate, version=3)
                result_truc_minrelay = node.submitpackage([tx_v3_0fee_parent["hex"], tx_v3_child_minrelay["hex"]])
                assert_equal(result_truc_minrelay["package_msg"], "transaction failed")

            tx_v2_0fee_parent = self.wallet.create_self_transfer(fee=0, fee_rate=0, confirmed_only=True, version=2)
            tx_v2_child = self.wallet.create_self_transfer(utxo_to_spend=tx_v2_0fee_parent["new_utxo"], fee_rate=high_feerate, version=2)
            total_v2_fee = tx_v2_child["fee"] + tx_v2_0fee_parent["fee"]
            total_v2_size = tx_v2_child["tx"].get_vsize() + tx_v2_0fee_parent["tx"].get_vsize()
            assert_greater_than_or_equal(total_v2_fee, get_fee(total_v2_size, minrelayfeerate))
            if minrelayfeerate > 0:
                assert_greater_than(get_fee(tx_v2_0fee_parent["tx"].get_vsize(), minrelayfeerate), 0)
                # Always need to pay at least 1 satoshi for entry, even if minimum feerate is very low
                assert_greater_than(total_v2_fee, 0)

            result_truc = node.submitpackage([tx_v3_0fee_parent["hex"], tx_v3_child["hex"]], maxfeerate=0)
            assert_equal(result_truc["package_msg"], "success")

            result_non_truc = node.submitpackage([tx_v2_0fee_parent["hex"], tx_v2_child["hex"]], maxfeerate=0)
            assert_equal(result_non_truc["package_msg"], "success")
            self.check_mempool([tx_v2_0fee_parent["txid"], tx_v2_child["txid"], tx_v3_0fee_parent["txid"], tx_v3_child["txid"]])


    def run_test(self):
        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 200)
        self.test_truc_max_vsize()
        self.test_truc_acceptance()
        self.test_truc_reorg()
        self.test_nondefault_package_limits()
        self.test_truc_ancestors_package()
        self.test_truc_ancestors_package_and_mempool()
        self.test_truc_package_inheritance()
        self.test_truc_in_testmempoolaccept()
        self.test_minrelay_in_package_combos()


if __name__ == "__main__":
    MempoolTRUC(__file__).main()
