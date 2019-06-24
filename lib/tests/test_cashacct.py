##!/usr/bin/env python3
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Cash Accounts tests.
'''
import unittest

from .. import cashacct
from ..address import Address

class TestCashAccounts(unittest.TestCase):

    def test_class_ScriptOutput(self):
        '''Test for the cashacct.ScriptOutput class'''

        valid_registration_scripts = [
            ( 'bv1', Address.from_string('bitcoincash:qzgvpjawln2l8wfmsg2qwnnytcua02hy45vpdvrqu5'),
              bytes.fromhex('6a040101010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad')),
            ( 'im_uname', Address.from_string('qqevtgm50kulte70smem643qs07fjkj47y5jv2d2v7'),
              bytes.fromhex('6a040101010108696d5f756e616d65150132c5a3747db9f5e7cf86f3bd562083fc995a55f1')),
            ( 'Mark', Address.from_string('qqy9myvyt7qffgye5a2mn2vn8ry95qm6asy40ptgx2'),
              bytes.fromhex('6a0401010101044d61726b1501085d91845f8094a099a755b9a99338c85a037aec')),
            ( 'Markk', Address.from_string('pqy9myvyt7qffgye5a2mn2vn8ry95qm6asnsjwvtah'),
              bytes.fromhex('6a0401010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec')),
        ]
        for name, address, b in valid_registration_scripts:
            so = cashacct.ScriptOutput(b)
            self.assertEqual(name, so.name)
            self.assertEqual(address, so.address)
            so2 = cashacct.ScriptOutput.create_registration(name, address)
            self.assertEqual(so2, so)
            self.assertEqual(so2.name, name)
            self.assertEqual(so2.address, address)
            self.assertFalse(so.is_complete())
            so3 = cashacct.ScriptOutput(so2, number=101, collision_hash='1234567890')
            self.assertEqual(so2, so3)
            so4 = cashacct.ScriptOutput(so2, number=101, collision_hash='1234567890')
            self.assertTrue(so4.is_complete())
            self.assertTrue(so3.make_complete(103, '0123456789'))
            self.assertRaises(Exception, so2.make_complete, 1, '12334567890')
            self.assertRaises(Exception, so2.make_complete, 'adasd', '12334567890')
            self.assertRaises(Exception, so2.make_complete, -1, '0123asdb2')
            self.assertRaises(Exception, so2.make_complete, 99, '0123456789')
        invalid_registration_scripts = [
            b'garbage',
            'wrongtype',  ['more wrong type'],
            # bad protocol header
            bytes.fromhex('6a040102010103627631150190c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            bytes.fromhex('6a070101010108696d5f756e616d65150132c5a3747db9f5e7cf86f3bd562083fc995a55f1'),
            # not op_return
            bytes.fromhex('6b0401010101044d61726b1501085d91845f8094a099a755b9a99338c85a037aec'),
            # bad pushdata
            bytes.fromhex('6a0301010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec'),
            # out of spec char in name
            bytes.fromhex('6a0401010101057d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec'),
            # empty name
            bytes.fromhex('6a0401010101001502085d91845f8094a099a755b9a99338c85a037aec'),
            # too long a name
            bytes.fromhex('6a04010101016561616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161611502085d91845f8094a099a755b9a99338c85a037aec'),
            # bad address type
            bytes.fromhex('6a040101010103627631150390c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            # bad length of pushdata
            bytes.fromhex('6a040101010103627631140190c0cbaefcd5f3b93b8214074e645e39d7aae4ad'),
            # extra garbage at the end
            bytes.fromhex('6a0401010101054d61726b6b1502085d91845f8094a099a755b9a99338c85a037aec6a6a6a6a6a6a'),
            # extra garbage at the end II
            bytes.fromhex('6a0401010101054d61726b6b15020102010201020102010201020102010201020102ffffffffffff'),
            # extra garbage at the end III
            bytes.fromhex('6a0401010101054d61726b6b150201020102010201020102010201020102010201025f4f3f2f1f8f'),
        ]
        for b in invalid_registration_scripts:
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput, b)
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput.from_script, b)
            self.assertRaises(cashacct.ArgumentError, cashacct.ScriptOutput.parse_script, b)
