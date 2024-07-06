# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2017 Neil Booth
# Copyright (C) 2023 The Electron Cash Developers
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

import json
import pkgutil

from .asert_daa import ASERTDaa, Anchor


def _read_json_dict(filename):
    try:
        data = pkgutil.get_data(__name__, filename)
        r = json.loads(data.decode('utf-8'))
    except:
        r = {}
    return r


class AbstractNet:
    TESTNET = False
    REGTEST = False
    LEGACY_POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60   # 2 weeks
    LEGACY_POW_TARGET_INTERVAL = 10 * 60  # 10 minutes
    LEGACY_POW_RETARGET_BLOCKS = LEGACY_POW_TARGET_TIMESPAN // LEGACY_POW_TARGET_INTERVAL  # 2016 blocks
    BASE_UNITS = {'BCH': 8, 'mBCH': 5, 'bits': 2}
    DEFAULT_UNIT = "BCH"
    RPA_START_HEIGHT = 0


class MainNet(AbstractNet):
    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    CASHADDR_PREFIX = "bitcoincash"
    RPA_PREFIX = "paycode"
    RPA_START_HEIGHT = 825000
    HEADERS_URL = "http://bitcoincash.com/files/blockchain_headers"  # Unused
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = _read_json_dict('servers.json')  # DO NOT MODIFY IN CLIENT CODE
    TITLE = 'Electron Cash'

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
    BITCOIN_CASH_FORK_BLOCK_HASH = "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"

    # Nov 13. 2017 HF to CW144 DAA height (height of last block mined on old DAA)
    CW144_HEIGHT = 504031

    # Note: this is not the Merkle root of the verification block itself , but a Merkle root of
    # all blockchain headers up until and including this block. To get this value you need to
    # connect to an ElectrumX server you trust and issue it a protocol command. This can be
    # done in the console as follows:
    #
    #    network.synchronous_get(("blockchain.block.header", [height, height]))
    #
    # Consult the ElectrumX documentation for more details.
    VERIFICATION_BLOCK_MERKLE_ROOT = "57df4f7554f68c091f278ccdfa48fe01e45b3ffb9c2fabaeede2c6d2c5784820"
    VERIFICATION_BLOCK_HEIGHT = 792773
    asert_daa = ASERTDaa(is_testnet=False)
    # Note: We *must* specify the anchor if the checkpoint is after the anchor, due to the way
    # blockchain.py skips headers after the checkpoint.  So all instances that have a checkpoint
    # after the anchor must specify the anchor as well.
    asert_daa.anchor = Anchor(height=661647, bits=402971390, prev_time=1605447844)

    # Version numbers for BIP32 extended keys
    # standard: xprv, xpub
    XPRV_HEADERS = {
        'standard': 0x0488ade4,
    }

    XPUB_HEADERS = {
        'standard': 0x0488b21e,
    }


class TestNet(AbstractNet):
    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    RPA_PREFIX = "paycodetest"
    HEADERS_URL = "http://bitcoincash.com/files/testnet_headers"  # Unused
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    DEFAULT_PORTS = {'t':'51001', 's':'51002'}
    DEFAULT_SERVERS = _read_json_dict('servers_testnet.json')  # DO NOT MODIFY IN CLIENT CODE
    TITLE = 'Electron Cash Testnet'
    BASE_UNITS = {'tBCH': 8, 'mtBCH': 5, 'tbits': 2}
    DEFAULT_UNIT = "tBCH"

    # Nov 13. 2017 HF to CW144 DAA height (height of last block mined on old DAA)
    CW144_HEIGHT = 1188697

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    BITCOIN_CASH_FORK_BLOCK_HASH = "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5"

    VERIFICATION_BLOCK_MERKLE_ROOT = "66dfe14adb3e7576977d2db610bce4b86360ea7c3a68f56342e63f5306c94f82"
    VERIFICATION_BLOCK_HEIGHT = 1534000
    asert_daa = ASERTDaa(is_testnet=True)
    asert_daa.anchor = Anchor(height=1421481, bits=486604799, prev_time=1605445400)

    # Version numbers for BIP32 extended keys
    # standard: tprv, tpub
    XPRV_HEADERS = {
        'standard': 0x04358394,
    }

    XPUB_HEADERS = {
        'standard': 0x043587cf,
    }


class TestNet4(TestNet):
    GENESIS = "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b"
    TITLE = 'Electron Cash Testnet4'

    HEADERS_URL = "http://bitcoincash.com/files/testnet4_headers"  # Unused

    DEFAULT_SERVERS = _read_json_dict('servers_testnet4.json')  # DO NOT MODIFY IN CLIENT CODE
    DEFAULT_PORTS = {'t': '62001', 's': '62002'}

    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 6
    BITCOIN_CASH_FORK_BLOCK_HASH = "00000000d71b9b1f7e13b0c9b218a12df6526c1bcd1b667764b8693ae9a413cb"

    # Nov 13. 2017 HF to CW144 DAA height (height of last block mined on old DAA)
    CW144_HEIGHT = 3000

    VERIFICATION_BLOCK_MERKLE_ROOT = "3f67f9cdb53e625f1ed52c1798c3bf329b3eccb23d6a933aca7b7703f4f1cdb9"
    VERIFICATION_BLOCK_HEIGHT = 128000
    asert_daa = ASERTDaa(is_testnet=True)  # Redeclare to get instance for this subclass
    asert_daa.anchor = Anchor(height=16844, bits=486604799, prev_time=1605451779)


class ChipNet(TestNet4):
    TITLE = 'Electron Cash Chipnet'
    HEADERS_URL = "http://bitcoincash.com/files/chipnet_headers"  # Unused
    DEFAULT_SERVERS = _read_json_dict('servers_chipnet.json')  # DO NOT MODIFY IN CLIENT CODE
    DEFAULT_PORTS = {'t': '64001', 's': '64002'}
    VERIFICATION_BLOCK_MERKLE_ROOT = "9af57abc210acda2cdfa95b61bef3ba319b16838a1833e581f3528266435ddee"
    VERIFICATION_BLOCK_HEIGHT = 128000


class ScaleNet(TestNet):
    GENESIS = "00000000e6453dc2dfe1ffa19023f86002eb11dbb8e87d0291a4599f0430be52"
    TITLE = 'Electron Cash Scalenet'
    BASE_UNITS = {'sBCH': 8, 'msBCH': 5, 'sbits': 2}
    DEFAULT_UNIT = "sBCH"

    HEADERS_URL = "http://bitcoincash.com/files/scalenet_headers"  # Unused

    DEFAULT_SERVERS = _read_json_dict('servers_scalenet.json')  # DO NOT MODIFY IN CLIENT CODE
    DEFAULT_PORTS = {'t': '63001', 's': '63002'}

    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 6
    BITCOIN_CASH_FORK_BLOCK_HASH = "000000000e16730d293050fc5fe5b0978b858f5d9d91192a5ca2793902493597"

    # Nov 13. 2017 HF to CW144 DAA height (height of last block mined on old DAA)
    CW144_HEIGHT = 3000

    VERIFICATION_BLOCK_MERKLE_ROOT = "41eb32849a353fcb408c8b25e84578c714dbdc5ee774d0fbe25e85755250df6a"
    VERIFICATION_BLOCK_HEIGHT = 2016
    asert_daa = ASERTDaa(is_testnet=False)  # Despite being a "testnet", ScaleNet uses 2d half-life
    asert_daa.anchor = None  # Intentionally not specified because it's after checkpoint; blockchain.py will calculate


class RegtestNet(TestNet):
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    TITLE = 'Electron Cash Regtest'
    BASE_UNITS = {'rBCH': 8, 'rsBCH': 5, 'rbits': 2}
    DEFAULT_UNIT = "rBCH"
    CASHADDR_PREFIX = "bchreg"
    REGTEST = True

    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 0
    BITCOIN_CASH_FORK_BLOCK_HASH = GENESIS

    VERIFICATION_BLOCK_HEIGHT = 100
    VERIFICATION_BLOCK_MERKLE_ROOT = None
    asert_daa = ASERTDaa(is_testnet=True) # not used on regtest

    DEFAULT_SERVERS = _read_json_dict('servers_regtest.json')  # DO NOT MODIFY IN CLIENT CODE


# All new code should access this to get the current network config.
net = MainNet


def _set_units():
    from . import util
    util.base_units = net.BASE_UNITS.copy()
    util.DEFAULT_BASE_UNIT = net.DEFAULT_UNIT
    util.recalc_base_units()


def set_mainnet():
    global net
    net = MainNet
    _set_units()


def set_testnet():
    global net
    net = TestNet
    _set_units()


def set_testnet4():
    global net
    net = TestNet4
    _set_units()


def set_scalenet():
    global net
    net = ScaleNet
    _set_units()

def set_regtest():
    global net
    net = RegtestNet
    _set_units()


def set_chipnet():
    global net
    net = ChipNet
    _set_units()


# Compatibility
def _instancer(cls):
    return cls()


@_instancer
class NetworkConstants:
    """ Compatibility class for old code such as extant plugins.

    Client code can just do things like:
    NetworkConstants.ADDRTYPE_P2PKH, NetworkConstants.DEFAULT_PORTS, etc.

    We have transitioned away from this class. All new code should use the
    'net' global variable above instead. """
    def __getattribute__(self, name):
        return getattr(net, name)

    def __setattr__(self, name, value):
        raise RuntimeError('NetworkConstants does not support setting attributes! ({}={})'.format(name,value))
