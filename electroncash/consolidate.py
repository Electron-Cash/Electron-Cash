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
from typing import Optional

from .address import Address
from .wallet import Abstract_Wallet


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
