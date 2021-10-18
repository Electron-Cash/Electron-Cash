import unittest
from unittest.mock import Mock

from .. import consolidate


class TestConsolidateCoinSelection(unittest.TestCase):
    def test_coin_selection(self) -> None:
        coins = {}
        v = 0
        for is_coinbase in (True, False):
            for is_frozen_coin in (True, False):
                for slp in (None, "not None"):
                    coins[f"dummy_txid:{v}"] = {
                        "value": v,
                        "coinbase": is_coinbase,
                        "is_frozen_coin": is_frozen_coin,
                        "slp_token": slp,
                    }
                    v += 1  # noqa: SIM113

        mock_wallet = Mock()
        mock_wallet.get_addr_utxo.return_value = coins

        for incl_coinbase in (True, False):
            for incl_noncoinbase in (True, False):
                for incl_frozen in (True, False):
                    for incl_slp in (True, False):
                        consolidator = consolidate.AddressConsolidator(
                            "address",
                            mock_wallet,
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
        self.assertListEqual([c["value"] for c in coins.values()], list(range(8)))

        consolidator = consolidate.AddressConsolidator(
            "address",
            mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=3,
            max_value_sats=None,
        )
        for coin in consolidator._coins:
            self.assertGreaterEqual(coin["value"], 3)
        self.assertEqual(len(consolidator._coins), 5)

        consolidator = consolidate.AddressConsolidator(
            "address",
            mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=None,
            max_value_sats=5,
        )
        for coin in consolidator._coins:
            self.assertLessEqual(coin["value"], 5)
        self.assertEqual(len(consolidator._coins), 6)

        consolidator = consolidate.AddressConsolidator(
            "address",
            mock_wallet,
            True,
            True,
            True,
            True,
            min_value_sats=3,
            max_value_sats=5,
        )
        for coin in consolidator._coins:
            self.assertGreaterEqual(coin["value"], 3)
            self.assertLessEqual(coin["value"], 5)
        self.assertEqual(len(consolidator._coins), 3)


def suite():
    test_suite = unittest.TestSuite()
    loadTests = unittest.defaultTestLoader.loadTestsFromTestCase
    test_suite.addTest(loadTests(TestConsolidateCoinSelection))
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
