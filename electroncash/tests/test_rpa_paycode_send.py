import shutil
import tempfile
import unittest
from unittest import mock

from .. import bitcoin
from .. import schnorr
from .. import storage
from ..address import Address, PublicKey
from ..rpa import paycode
from ..simple_config import SimpleConfig
from ..transaction import Transaction

from .test_rpa_standard_wallet import (
    _make_bip39_wallet,
    _make_electrum_wallet,
    _test_wif,
)


def _foreign_address():
    # An address the test wallets do not hold a key for.
    pubkey_hex = bitcoin.public_key_from_private_key(bytes([7]) * 32, True)
    return Address.from_pubkey(pubkey_hex)


def _fund_wallet(w, address, sats=100000):
    """Give the wallet a spendable coin offline by injecting a fake incoming
    tx. Only the output matters for the receiving wallet's bookkeeping; the
    input references a null prevout with a dummy signature so the tx
    serializes as complete and has a txid."""
    pubkey_hex = bitcoin.public_key_from_private_key(bytes([7]) * 32, True)
    txin = {
        'prevout_hash': '00' * 32,
        'prevout_n': 0,
        'address': _foreign_address(),
        'type': 'p2pkh',
        'signatures': ['00' * 0x48],
        'x_pubkeys': [pubkey_hex],
        'pubkeys': [pubkey_hex],
        'num_sig': 1,
        'sequence': 0xffffffff,
    }
    tx = Transaction.from_io([txin], [(bitcoin.TYPE_ADDRESS, address, sats)])
    # Mirror the synchronizer's order: history first, then the tx itself
    # (get_addr_io only credits coins whose tx is in the address history).
    w.receive_history_callback(address, [(tx.txid(), 1)], {})
    w.receive_tx_callback(tx.txid(), tx, 1)


class TestInputZeroSigningKey(unittest.TestCase):
    """_input_zero_signing_key must resolve the key for any wallet-owned
    address — including RPA-imported ones, which the old main-keystore-only
    lookup missed (UnboundLocalError)."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_hd_address(self, _mock_write):
        w = _make_electrum_wallet()
        addr = w.get_receiving_addresses()[0]
        sec, compressed, pubkey = paycode._input_zero_signing_key(
            w, {'address': addr}, None)
        self.assertEqual(pubkey.hex(), w.get_public_key(addr))
        self.assertEqual(bitcoin.serialize_privkey(sec, compressed, 'p2pkh'),
                         w.export_private_key(addr, None))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_imported_address(self, _mock_write):
        w = _make_electrum_wallet()
        w.enable_rpa(None)
        w.import_rpa_private_key(_test_wif(), None)
        rpa_addr = w.keystore_rpa_imported.get_addresses()[0]

        sec, compressed, pubkey = paycode._input_zero_signing_key(
            w, {'address': rpa_addr}, None)

        self.assertEqual(sec, bytes(range(1, 33)))
        self.assertTrue(compressed)
        expected_pubkey = PublicKey.from_WIF_privkey(_test_wif()).to_ui_string()
        self.assertEqual(pubkey.hex(), expected_pubkey)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_unknown_address_raises(self, _mock_write):
        w = _make_electrum_wallet()
        with self.assertRaisesRegex(Exception, 'not found'):
            paycode._input_zero_signing_key(
                w, {'address': _foreign_address()}, None)


@unittest.skipUnless(schnorr.has_fast_sign() and schnorr.has_fast_verify(),
                     'Schnorr fast signing unavailable (libsecp256k1 not built)')
class TestSendToPaycode(unittest.TestCase):
    """End-to-end (offline): build, sign and grind a paycode send."""

    def setUp(self):
        self.user_dir = tempfile.mkdtemp()
        self.config = SimpleConfig({'electron_cash_path': self.user_dir})

    def tearDown(self):
        shutil.rmtree(self.user_dir)

    def _make_receiver(self):
        # 4-bit prefix keeps the grind to ~16 expected iterations.
        r = _make_bip39_wallet()
        r.enable_rpa(None)
        return r, paycode.generate_paycode(r, prefix_size="04")

    def _send(self, sender, paycode_str):
        """Returns (raw_tx_hex, deserialized Transaction)."""
        sender.storage.put('sign_schnorr', True)
        raw = paycode.generate_transaction_from_paycode(
            sender, self.config, '0.0005', paycode_str, fee='0.00001',
            password=None)
        self.assertIsInstance(raw, str)
        self.assertTrue(raw)
        tx = Transaction(raw)
        tx.deserialize()
        return raw, tx

    def _assert_ground_prefix_matches(self, tx, receiver):
        scanpubkey = receiver.derive_pubkeys_rpa(3, 0)
        prefix_target = scanpubkey[2:3].lower()
        txin0 = tx._inputs[0]
        ser = tx.serialize_input_bytes(
            txin0, bytes.fromhex(tx.input_script(txin0)))
        self.assertEqual(bitcoin.Hash(ser)[:2].hex()[0:1], prefix_target)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_send_with_rpa_input_zero(self, _mock_write):
        """The bug scenario: the only spendable coin is RPA-imported, so it
        must end up as input 0 of the paycode send."""
        receiver, pc = self._make_receiver()
        sender = _make_electrum_wallet()
        sender.enable_rpa(None)
        sender.import_rpa_private_key(_test_wif(), None)
        rpa_addr = sender.keystore_rpa_imported.get_addresses()[0]
        _fund_wallet(sender, rpa_addr)

        _raw, tx = self._send(sender, pc)

        self.assertTrue(tx.is_complete())
        self.assertEqual(tx._inputs[0]['address'], rpa_addr)
        self._assert_ground_prefix_matches(tx, receiver)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_send_with_hd_input_zero(self, _mock_write):
        """Regression guard: the previously-working HD path still works after
        the key-resolution refactor."""
        receiver, pc = self._make_receiver()
        sender = _make_electrum_wallet()
        hd_addr = sender.get_receiving_addresses()[0]
        _fund_wallet(sender, hd_addr)

        _raw, tx = self._send(sender, pc)

        self.assertTrue(tx.is_complete())
        self.assertEqual(tx._inputs[0]['address'], hd_addr)
        self._assert_ground_prefix_matches(tx, receiver)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_paycode_round_trip_extraction(self, _mock_write):
        """The receiver must be able to detect the payment and extract the
        one-time private key from the tx the sender ground."""
        receiver, pc = self._make_receiver()
        sender = _make_electrum_wallet()
        sender.enable_rpa(None)
        sender.import_rpa_private_key(_test_wif(), None)
        _fund_wallet(sender, sender.keystore_rpa_imported.get_addresses()[0])

        raw, tx = self._send(sender, pc)

        wifs = receiver.extract_private_keys_from_transaction(raw, None)
        self.assertEqual(len(wifs), 1)
        extracted_addr = PublicKey.from_WIF_privkey(wifs[0]).address
        self.assertIn(extracted_addr, [addr for _, addr, _ in tx.outputs()])
