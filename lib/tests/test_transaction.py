import unittest
from lib import transaction
from lib.bitcoin import TYPE_ADDRESS

import pprint
from lib.keystore import xpubkey_to_address

v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"

class TestBCDataStream(unittest.TestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEquals(s.input.encode('hex'),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEquals(s.read_compact_size(), v)

        with self.assertRaises(IndexError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEquals(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        s.write('foobar')
        self.assertEquals(s.read_bytes(3), 'foo')
        self.assertEquals(s.read_bytes(2), 'ba')
        self.assertEquals(s.read_bytes(4), 'r')
        self.assertEquals(s.read_bytes(1), '')

class TestTransaction(unittest.TestCase):

    def test_deserialization(self):
        for sample in sample_tx:
            if 'raw' in sample and 'tx' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.deserialize(), sample['tx'])
            if 'raw_unsigned' in sample and 'tx_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.deserialize(), sample['tx_unsigned'])

    def test_outputs(self):
        for sample in sample_tx:
            if 'raw' in sample and 'outputs' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.get_outputs(), sample['outputs'])
            if 'raw_unsigned' in sample and 'outputs' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.get_outputs(), sample['outputs'])

    def test_outputaddresses(self):
        for sample in sample_tx:
            if 'raw' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.get_output_addresses(), sample['outputaddresses'])
            if 'raw_unsigned' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.get_output_addresses(), sample['outputaddresses'])

    def test_has_address(self):
        for sample in sample_tx:
            if 'raw' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw'])
                for a in sample['outputaddresses']:
                    self.assertTrue(tx.has_address(a))
                self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))
            if 'raw_unsigned' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                for a in sample['outputaddresses']:
                    self.assertTrue(tx.has_address(a))
                self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

    def test_update_signatures(self):
        # we dont have any samples for this yet
        for sample in sample_tx:
            if 'raw' in sample and 'raw_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                tx.update_signatures(sample['raw'])
                self.assertEquals(tx.raw, sample['raw'])
            elif 'raw' in sample:
                tx = transaction.Transaction(sample['raw'])
                tx.update_signatures(sample['raw'])
                self.assertEquals(tx.raw, sample['raw'])

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEquals(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', '19h943e4diLc68GXW7G75QNe2KWuMu7BaJ'))

        res = xpubkey_to_address('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5')
        self.assertEquals(res, ('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5', '1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEquals(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent


# sample test transactions
# list of samples, each sample will be tested depending on supplied parameters
# each sample is a dict of
#       raw - signed tx blob
#       tx - expected deserialization of 'raw'
#       raw_unsigned - unsigned tx blob
#       tx_unsigned - expected deserialization of 'raw_unsigned'
#       outputs - expected output of tx.get_outputs()
#       ouputaddresses - expected output of tx.get_output_addresses(), also used to test tx.has_address()
sample_tx = [
    { 'raw_unsigned': '0100000001f67f0082045b3da782a3c44ff677e8f6f711fc8bf744c85298f8f15883b0fce7000000005701ff4c53ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000feffffff022c970000000000001976a914e045289a6ba6806055b2e9aa96dd92ad83afc18888ac50c30000000000001976a914b6d22863dfffe257f72ed5ad6daaef8ba970139e88ac00000000',
      'tx_unsigned': {
            "inputs": [
                {
                    "address": None,
                    "num_sig": 0,
                    "prevout_hash": "e7fcb08358f1f89852c844f78bfc11f7f6e877f64fc4a382a73d5b0482007ff6",
                    "prevout_n": 0,
                    "pubkeys": [],
                    "scriptSig": "01ff4c53ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000",
                    "sequence": 4294967294,
                    "signatures": {},
                    "type": "unknown",
                    "x_pubkeys": []
                }
            ],
            "lockTime": 0,
            "outputs": [
                {
                    "address": "1MSqDCGMS8XVqNUiKzy2Vg4RZNb7Q4Sx6C",
                    "prevout_n": 0,
                    "scriptPubKey": "76a914e045289a6ba6806055b2e9aa96dd92ad83afc18888ac",
                    "type": 0,
                    "value": 38700
                },
                {
                    "address": "1Hffjw1mVEcsTCM6QEXBFXJUTWkwSSypxh",
                    "prevout_n": 1,
                    "scriptPubKey": "76a914b6d22863dfffe257f72ed5ad6daaef8ba970139e88ac",
                    "type": 0,
                    "value": 50000
                }
            ],
            "version": 1
        },
      'outputs': [('1MSqDCGMS8XVqNUiKzy2Vg4RZNb7Q4Sx6C', 38700), ('1Hffjw1mVEcsTCM6QEXBFXJUTWkwSSypxh', 50000)],
      'outputaddresses': ['1MSqDCGMS8XVqNUiKzy2Vg4RZNb7Q4Sx6C', '1Hffjw1mVEcsTCM6QEXBFXJUTWkwSSypxh']
    }
]