#!/usr/bin/env python3
# Electrum ABC - lightweight eCash client
# Copyright (C) 2021 The Electrum ABC developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
This module provides coin consolidation tools.
"""
from typing import List, Optional

from .address import Address
from .bitcoin import TYPE_ADDRESS
from .transaction import Transaction
from .wallet import Abstract_Wallet

MAX_STANDARD_TX_SIZE: int = 100_000
"""Maximum size for transactions that nodes are willing to relay/mine.
"""

MAX_TX_SIZE: int = 1_000_000
"""
Maximum allowed size for a transaction in a block.
"""

FEE_PER_BYTE: int = 1


class AddressConsolidator:
    """Consolidate coins for a single address in a wallet."""

    def __init__(
        self,
        address: Address,
        wallet: Abstract_Wallet,
        include_coinbase: bool = True,
        include_non_coinbase: bool = True,
        include_frozen: bool = False,
        include_slp: bool = False,
        min_value_sats: Optional[int] = None,
        max_value_sats: Optional[int] = None,
    ):
        self._coins = [
            utxo
            for utxo in wallet.get_addr_utxo(address).values()
            if (
                (include_coinbase or not utxo["coinbase"])
                and (include_non_coinbase or utxo["coinbase"])
                and (include_slp or utxo["slp_token"] is None)
                and (include_frozen or not utxo["is_frozen_coin"])
                and (min_value_sats is None or utxo["value"] >= min_value_sats)
                and (max_value_sats is None or utxo["value"] <= max_value_sats)
            )
        ]
        for c in self._coins:
            wallet.add_input_info(c)

        self.wallet = wallet

    def get_unsigned_transactions(
        self, output_address: Address, max_tx_size: int = MAX_STANDARD_TX_SIZE
    ) -> List[Transaction]:
        """
        Build as many raw transactions as needed to consolidate the coins.

        :param output_address: Make all transactions send the total amount to this
            address.
        :param max_tx_size: Maximum tx size in bytes. This is what limits the
            number of inputs per transaction.
        :return:
        """
        assert max_tx_size < MAX_TX_SIZE
        placeholder_amount = 200
        transactions = []
        while self._coins:
            tx_size = 0
            amount = 0
            tx = Transaction(None)
            tx.set_inputs([])
            while tx_size < max_tx_size and self._coins:
                dummy_tx = Transaction(None)
                dummy_tx.set_inputs(tx.inputs() + [self._coins[0]])
                dummy_tx.set_outputs(
                    [(TYPE_ADDRESS, output_address, placeholder_amount)]
                )
                tx_size = len(dummy_tx.serialize(estimate_size=True)) // 2

                if tx_size < max_tx_size:
                    amount = amount + self._coins[0]["value"]
                    tx.add_inputs([self._coins.pop(0)])
                    tx.set_outputs(
                        [
                            (
                                TYPE_ADDRESS,
                                output_address,
                                amount - tx_size * FEE_PER_BYTE,
                            )
                        ]
                    )

            transactions.append(tx)
        return transactions
