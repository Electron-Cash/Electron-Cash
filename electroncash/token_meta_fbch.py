#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
#
# Contributed by 2qx for Future Bitcoin Cash
#
# Part of the Electron Cash SPV Wallet
# License: MIT

from typing import Optional

from electroncash import util

BATON = "fbc0b001313509454331f23f4b1891a8d9a284421efcc33187f1a1cdd37ccb46"

GANTRY_ADDRESSES = [
    "pw4au340uajkakz7j2afhetzs6aw20mhxgfn83mlk0depc5yghspqqqckly70",
    "pw9chw4eqgllfj2w8wj935snchmznn6d9a6s4qf78p2l4zug7ausqxsg2dxve",
    "pdk0tnv5fjnu730d8gc82620af0h4kfdqqghsnyfvguqf9jnuszljj3fnpfhq",
    "pd8p4pnfya0skhqaa2slz6x7g2dgm3fljxkvfzwmeqvj884ung24w2mx7x8yd",
]


COLOR_CODES = [
    "000",
    "966424",
    "f00",
    "ff7500",
    "ff0",
    "0f0",
    "00f",
    "f0f",
    "888",
    "fff",
]


class EmbeddedMetaData:
    """Encapsulates FBCH embedded metadata"""

    __slots__ = ("name", "description", "decimals", "symbol", "icon", "icon_ext")

    name: str
    description: str
    decimals: int
    symbol: str
    icon: Optional[bytes]
    icon_ext: Optional[str]

    def __init__(self):
        self.name = self.description = self.symbol = ""
        self.decimals = 0
        self.icon = self.icon_ext = None

    def __repr__(self):
        icon_thing = len(self.icon) if self.icon is not None else None
        return (
            f"<TemplateMetaData name={self.name} description={self.description} decimals={self.decimals}"
            f" symbol={self.symbol}, icon_ext={self.icon_ext} icon={icon_thing} bytes>"
        )


def get_places(series):
    return [int(a) for a in str(f"{int(series/1000):04}")]


def get_fbch_icon_svg_uri(series, size=400):
    places = get_places(series)
    return ''.join(
            [
                f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 160 160' style='width:{size}px; height: {size}px;'>",
                f"<path d='M 10 10 L 10 150 150 150 150 10 Z' style='stroke-width: 2px; stroke-linejoin: miter; stroke-linecap: butt; stroke: #fff; fill:#{COLOR_CODES[places[0]]}; paint-order:stroke'></path>",
                f"<path d='M 20 20 L 50 20 50 30 30 30 30 40 40 40 40 50 30 50 30 70 20 70 Z' style='fill: #fff;'></path>",
                f"<path d='M 20 80 L 20 150 50 150 50 80 Z' style='fill: #{COLOR_CODES[places[1]]};'></path>",
                f"<path d='M 60 70 L 60 150 140 150 140 70 Z' style='fill:#{COLOR_CODES[places[3]]};'></path>",
                f"<path d='M 60 20 L 60 60 140 60 140 20 Z' style='fill:#{COLOR_CODES[places[2]]};'></path></svg>",
            ]
        ).encode()


def validate_pre_genesis_bchn(transaction):
    
    # Get the first cashaddr,
    addr_or_script = str(transaction.get_output_addresses()[0])
    
    # Get the first output commitment and category
    output0tokenData = transaction.token_datas()[0]
    output0Category = output0tokenData.id[::-1].hex()

    # If the first output of the pre-genesis transaction
    # was sent to a valid gantry and it carried the minting baton...
    if addr_or_script in GANTRY_ADDRESSES and output0Category == BATON:
        # Get the series
        series = int.from_bytes(
            output0tokenData.commitment, byteorder="little", signed=False
        )

        # Return the series.
        return series
    else:
        return False



def try_to_get_fbch_metadata(wallet, token_id_hex, timeout=30):
    
    """This is potentially slow because it does go out to the network, but only requires one request."""
    assert isinstance(token_id_hex, str) and len(token_id_hex) == 64
    # First, see if it's a wallet tx, find the pre-genesis
    try:
        tx = wallet.try_to_get_tx(
            token_id_hex, allow_network_lookup=True, timeout=timeout
        )
    except util.TimeoutException as e:
        util.print_error(
            f"Failed to get pre-genesis tx for {token_id_hex}; got exception: {e!r}"
        )
        return None
    if not tx:
        util.print_error(f"Failed to get pre-genesis tx for {token_id_hex}; not found")
        return None

    series = validate_pre_genesis_bchn(tx)
    
    # Some basic sanity checks on top of baton validation.
    if isinstance(series, int) and series > 860000:
        md = EmbeddedMetaData()
        md.decimals = 8
        md.symbol = f"FBCH-{series:07}"
        md.name = f"Future BCH {series:n}"
        md.description = (
            f"A token representing Bitcoin Cash locked until block {series:n}"
        )
        md.icon = get_fbch_icon_svg_uri(series)
        md.icon_ext = ".svg"
        return md
    else:
        return None
