import math
import unittest
from unittest.mock import Mock

from .. import consolidate
from ..address import Address

TEST_ADDRESS: Address = Address.from_string(
    "ecash:qr3l6uufcuwm9prgpa6cfxnez87fzstxesp7ugp0ez"
)

FEERATE: int = 1
"""Satoshis per byte"""


class TestConsolidateCoinSelection(unittest.TestCase):
    def setUp(self) -> None:
        coins = {}
        i = 0
        for is_coinbase in (True, False):
            for is_frozen_coin in (True, False):
                for slp in (None, "not None"):
                    coins[f"dummy_txid:{i}"] = {
                        "address": TEST_ADDRESS,
                        "prevout_n": i,
                        "prevout_hash": "a" * 64,
                        "height": 1,
                        "value": 1000 + i,
                        "coinbase": is_coinbase,
                        "is_frozen_coin": is_frozen_coin,
                        "slp_token": slp,
                        "type": "p2pkh",
                    }
                    i += 1  # noqa: SIM113

        self.mock_wallet = Mock()
        self.mock_wallet.get_addr_utxo.return_value = coins

    def test_coin_selection(self) -> None:
        for incl_coinbase in (True, False):
            for incl_noncoinbase in (True, False):
                for incl_frozen in (True, False):
                    for incl_slp in (True, False):
                        consolidator = consolidate.AddressConsolidator(
                            "address",
                            self.mock_wallet,
                            incl_coinbase,
                            incl_noncoinbase,
                            incl_frozen,
                            incl_slp,
                        )
                        for coin in consolidator._coins:
                            if not incl_coinbase:
                                self.assertFalse(coin["coinbase"])
                            if not incl_noncoinbase:
                                self.assertTrue(coin["coinbase"])
                            if not incl_frozen:
                                self.assertFalse(coin["is_frozen_coin"])
                            if not incl_slp:
                                self.assertIsNone(coin["slp_token"])

        # test minimum and maximum value
        consolidator = consolidate.AddressConsolidator(
            "address",
            self.mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=1003,
            max_value_sats=None,
        )
        for coin in consolidator._coins:
            self.assertGreaterEqual(coin["value"], 1003)
        self.assertEqual(len(consolidator._coins), 5)

        consolidator = consolidate.AddressConsolidator(
            "address",
            self.mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=None,
            max_value_sats=1005,
        )
        for coin in consolidator._coins:
            self.assertLessEqual(coin["value"], 1005)
        self.assertEqual(len(consolidator._coins), 6)

        consolidator = consolidate.AddressConsolidator(
            "address",
            self.mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=1003,
            max_value_sats=1005,
        )
        for coin in consolidator._coins:
            self.assertGreaterEqual(coin["value"], 1003)
            self.assertLessEqual(coin["value"], 1005)
        self.assertEqual(len(consolidator._coins), 3)

    def test_get_unsigned_transactions(self):
        for size in range(200, 1500, 100):
            # select all coins
            consolidator = consolidate.AddressConsolidator(
                "address",
                self.mock_wallet,
                True,
                True,
                True,
                True,
                min_value_sats=None,
                max_value_sats=None,
            )
            txs = consolidator.get_unsigned_transactions(
                output_address=TEST_ADDRESS,
                max_tx_size=size,
            )

            # tx size is roughly 148 * n_in + 34 * n_out + 10
            expected_n_inputs_for_size = (size - 44) // 148
            self.assertEqual(len(txs), math.ceil(8 / expected_n_inputs_for_size))

            # Check the fee and amount
            total_inputs = 0
            total_outputs = 0
            total_fee = 0
            total_size = 0
            for tx in txs:
                tx_size = len(tx.serialize(estimate_size=True)) // 2
                self.assertEqual(tx.get_fee(), tx_size * FEERATE)
                total_fee += tx.get_fee()
                total_inputs += tx.input_value()
                total_outputs += tx.output_value()
                total_size += tx_size
            self.assertEqual(total_inputs, sum(range(1000, 1008)))
            self.assertEqual(total_outputs, total_inputs - total_fee)
            self.assertEqual(total_fee, total_size * FEERATE)


def suite():
    test_suite = unittest.TestSuite()
    loadTests = unittest.defaultTestLoader.loadTestsFromTestCase
    test_suite.addTest(loadTests(TestConsolidateCoinSelection))
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
