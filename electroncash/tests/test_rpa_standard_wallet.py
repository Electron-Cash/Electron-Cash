import unittest
from unittest import mock

from .. import bitcoin
from .. import keystore
from .. import storage
from .. import wallet
from ..address import PublicKey
from ..rpa import paycode as rpa_paycode
from ..util import InvalidPassword


_ELECTRUM_SEED = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
_BIP39_SEED = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'


def _make_electrum_wallet():
    ks = keystore.from_seed(_ELECTRUM_SEED, '', False)
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', 1)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    return w


def _make_bip39_wallet():
    ks = keystore.from_seed(_BIP39_SEED, '', seed_type='bip39',
                             derivation="m/44'/145'/0'")
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', 1)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    return w


def _test_wif():
    # deterministic test key: bytes 1..32 (valid secp256k1 scalar)
    return bitcoin.serialize_privkey(bytes(range(1, 33)), True, 'p2pkh')


class TestRpaStandardWallet(unittest.TestCase):

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_electrum_seed(self, _mock_write):
        """enable_rpa() sets up keystore_rpa_aux at the wallet's account node for Electrum seeds."""
        w = _make_electrum_wallet()
        self.assertFalse(w.is_rpa_enabled())
        self.assertIsNone(w.keystore_rpa_aux)

        w.enable_rpa(None)

        self.assertTrue(w.is_rpa_enabled())
        self.assertIsNotNone(w.keystore_rpa_aux)
        # Electrum seeds use m/ as account node
        self.assertEqual(w.keystore_rpa_aux.derivation, "m/")
        self.assertTrue(w.keystore_rpa_aux.xpub.startswith('xpub'))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_bip39_seed(self, _mock_write):
        """enable_rpa() sets up keystore_rpa_aux at the wallet's account node for BIP39 seeds."""
        w = _make_bip39_wallet()
        self.assertFalse(w.is_rpa_enabled())

        w.enable_rpa(None)

        self.assertTrue(w.is_rpa_enabled())
        self.assertIsNotNone(w.keystore_rpa_aux)
        # BIP39 wallet uses m/44'/145'/0' as account node
        self.assertEqual(w.keystore_rpa_aux.derivation, "m/44'/145'/0'")
        self.assertTrue(w.keystore_rpa_aux.xpub.startswith('xpub'))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_paycode_uses_chain_3(self, _mock_write):
        """RPA scan key is at {keystore.derivation}/3/0, distinct from {keystore.derivation}/0/0."""
        w = _make_electrum_wallet()
        w.enable_rpa(None)

        scan_pubkey = w.derive_pubkeys_rpa(3, 0)
        spend_pubkey = w.derive_pubkeys_rpa(3, 1)
        # {keystore.derivation}/0/0 is the first normal receive key
        first_receive_key = w.keystore_rpa_aux.derive_pubkey(0, 0)

        self.assertNotEqual(
            scan_pubkey, first_receive_key,
            "RPA scan key ({keystore.derivation}/3/0) must differ from first receive key ({keystore.derivation}/0/0)"
        )
        self.assertNotEqual(scan_pubkey, spend_pubkey)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_get_addresses_includes_rpa_imported(self, _mock_write):
        """get_addresses() returns HD addresses plus any RPA-imported addresses."""
        w = _make_electrum_wallet()
        w.enable_rpa(None)

        addrs_before = w.get_addresses()

        w.import_rpa_private_key(_test_wif(), None)

        addrs_after = w.get_addresses()
        self.assertGreater(len(addrs_after), len(addrs_before))

        rpa_addrs = w.keystore_rpa_imported.get_addresses()
        self.assertEqual(len(rpa_addrs), 1)
        self.assertIn(rpa_addrs[0], addrs_after)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_add_input_sig_info_routes_rpa_imported_key(self, _mock_write):
        """add_input_sig_info routes RPA-imported addresses through keystore_rpa_imported."""
        w = _make_electrum_wallet()
        w.enable_rpa(None)

        w.import_rpa_private_key(_test_wif(), None)
        rpa_addr = w.keystore_rpa_imported.get_addresses()[0]

        txin = {'type': 'p2pkh', 'address': rpa_addr}
        w.add_input_sig_info(txin, rpa_addr)

        expected_pubkey = (
            w.keystore_rpa_imported.address_to_pubkey(rpa_addr).to_ui_string()
        )
        self.assertEqual(txin['x_pubkeys'], [expected_pubkey])
        self.assertEqual(txin['num_sig'], 1)
        self.assertEqual(txin['signatures'], [None])


def _make_rpa_wallet_with_imported_key():
    w = _make_electrum_wallet()
    w.enable_rpa(None)
    w.import_rpa_private_key(_test_wif(), None)
    return w, w.keystore_rpa_imported.get_addresses()[0]


class TestRpaImportedAddressOps(unittest.TestCase):
    """Index-based wallet operations (get_address_index and friends) must work
    for addresses that exist only in keystore_rpa_imported."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_get_address_index_rpa_imported(self, _mock_write):
        """get_address_index returns the imported pubkey for RPA addresses and
        keeps the (change, n) tuple contract for HD addresses."""
        w, rpa_addr = _make_rpa_wallet_with_imported_key()

        index = w.get_address_index(rpa_addr)
        self.assertEqual(index, w.keystore_rpa_imported.address_to_pubkey(rpa_addr))

        hd_addr = w.get_receiving_addresses()[0]
        self.assertEqual(w.get_address_index(hd_addr), (False, 0))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_export_private_key_rpa_imported(self, _mock_write):
        """export_private_key round-trips the imported WIF."""
        w, rpa_addr = _make_rpa_wallet_with_imported_key()
        self.assertEqual(w.export_private_key(rpa_addr, None), _test_wif())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_export_all_addresses_does_not_raise(self, _mock_write):
        """Exporting every wallet address must succeed — mirrors the GUI's
        'Export private keys' loop, which iterates get_addresses()."""
        w, _rpa_addr = _make_rpa_wallet_with_imported_key()
        for addr in w.get_addresses():
            wif = w.export_private_key(addr, None)
            self.assertTrue(wif)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_get_public_keys_rpa_imported(self, _mock_write):
        """get_public_key(s) return the imported pubkey hex for RPA addresses."""
        w, rpa_addr = _make_rpa_wallet_with_imported_key()
        expected = PublicKey.from_WIF_privkey(_test_wif()).to_ui_string()
        self.assertEqual(w.get_public_key(rpa_addr), expected)
        self.assertEqual(w.get_public_keys(rpa_addr), [expected])

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sign_message_rpa_imported(self, _mock_write):
        """sign_message works for an RPA-imported address and verifies."""
        w, rpa_addr = _make_rpa_wallet_with_imported_key()
        msg = b'test rpa message'
        sig = w.sign_message(rpa_addr, msg, None)
        self.assertTrue(bitcoin.verify_message(rpa_addr, sig, msg))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_sign_message_hd_address_unaffected(self, _mock_write):
        """sign_message still delegates to the HD keystore for HD addresses."""
        w, _rpa_addr = _make_rpa_wallet_with_imported_key()
        hd_addr = w.get_receiving_addresses()[0]
        msg = b'test hd message'
        sig = w.sign_message(hd_addr, msg, None)
        self.assertTrue(bitcoin.verify_message(hd_addr, sig, msg))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_export_private_key_wrong_password_raises_invalid_password(self, _mock_write):
        """A wrong password raises InvalidPassword specifically — the GUI export
        dialog's error handling depends on that exception type."""
        w, rpa_addr = _make_rpa_wallet_with_imported_key()
        w.update_password(None, 'topsecret')
        with self.assertRaises(InvalidPassword):
            w.export_private_key(rpa_addr, 'wrong')
        self.assertEqual(w.export_private_key(rpa_addr, 'topsecret'), _test_wif())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_decrypt_message_rpa_imported(self, _mock_write):
        """decrypt_message routes to keystore_rpa_imported when the pubkey is an
        imported RPA key."""
        w, _rpa_addr = _make_rpa_wallet_with_imported_key()
        pubkey_hex = PublicKey.from_WIF_privkey(_test_wif()).to_ui_string()
        encrypted = bitcoin.encrypt_message(b'hello rpa', pubkey_hex)
        self.assertEqual(w.decrypt_message(pubkey_hex, encrypted, None), b'hello rpa')


class TestRpaScanHeight(unittest.TestCase):
    """rpa_height must always resolve to a server-independent height:
    stored value -> seed-creation-date estimate -> RPA genesis."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_height_prefers_stored_value(self, _mock_write):
        w = _make_electrum_wallet()
        w.rpa_height = 812345
        self.assertEqual(w.rpa_height, 812345)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_height_falls_back_to_seed_ts(self, _mock_write):
        """A stored seed creation date narrows the scan window."""
        seed_ts = 1750000000  # mid-2025
        ks = keystore.from_seed(_ELECTRUM_SEED, '', False)
        store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
        store.put('keystore', ks.dump())
        store.put('gap_limit', 1)
        store.put('seed_ts', seed_ts)
        w = wallet.Standard_Wallet(store)
        w.synchronize()

        self.assertEqual(w.rpa_height,
                         rpa_paycode.determine_best_rpa_start_height(seed_ts))
        self.assertGreater(w.rpa_height,
                           rpa_paycode.determine_best_rpa_start_height())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_height_defaults_to_rpa_genesis(self, _mock_write):
        """No seed_ts and no network attached: the start height must be
        server-independent (regression test for the tip-100 silent miss)."""
        w = _make_electrum_wallet()
        self.assertEqual(w.rpa_height,
                         rpa_paycode.determine_best_rpa_start_height())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_reset_rpa_scan_height(self, _mock_write):
        w = _make_electrum_wallet()
        w.rpa_height = 812345
        w.reset_rpa_scan_height()
        self.assertIsNone(w.storage.get('rpa_height'))
        self.assertEqual(w.rpa_height,
                         rpa_paycode.determine_best_rpa_start_height())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_height_is_int_when_enabled(self, _mock_write):
        """RpaManager relies on rpa_height always resolving to a height."""
        w = _make_electrum_wallet()
        w.enable_rpa(None)
        self.assertIsInstance(w.rpa_height, int)
