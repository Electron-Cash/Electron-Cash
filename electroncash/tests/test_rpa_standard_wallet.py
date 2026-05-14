import unittest
from unittest import mock

from .. import bitcoin
from .. import keystore
from .. import storage
from .. import wallet


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
        """enable_rpa() sets up keystore_rpa_aux at m/44'/145'/8' for Electrum seeds."""
        w = _make_electrum_wallet()
        self.assertFalse(w.is_rpa_enabled())
        self.assertIsNone(w.keystore_rpa_aux)

        w.enable_rpa(None)

        self.assertTrue(w.is_rpa_enabled())
        self.assertIsNotNone(w.keystore_rpa_aux)
        self.assertEqual(w.keystore_rpa_aux.derivation, "m/44'/145'/8'")
        self.assertTrue(w.keystore_rpa_aux.xpub.startswith('xpub'))
        # RPA keystore is at a different path, so its xpub must differ from main
        self.assertNotEqual(w.keystore_rpa_aux.xpub, w.keystore.xpub)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_bip39_seed(self, _mock_write):
        """enable_rpa() sets up keystore_rpa_aux at m/44'/145'/8' for BIP39 seeds."""
        w = _make_bip39_wallet()
        self.assertFalse(w.is_rpa_enabled())

        w.enable_rpa(None)

        self.assertTrue(w.is_rpa_enabled())
        self.assertIsNotNone(w.keystore_rpa_aux)
        self.assertEqual(w.keystore_rpa_aux.derivation, "m/44'/145'/8'")
        self.assertTrue(w.keystore_rpa_aux.xpub.startswith('xpub'))
        self.assertNotEqual(w.keystore_rpa_aux.xpub, w.keystore.xpub)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_paycode_differs_from_legacy_rpa_wallet(self, _mock_write):
        """Standard_Wallet RPA scan key is at m/44'/145'/8'/0/0, not the root m/0/0."""
        w = _make_electrum_wallet()
        w.enable_rpa(None)

        # Simulate legacy RpaWallet: keystore_rpa_aux is derived at the root (m/)
        bip32_seed = keystore.Mnemonic_Electrum.mnemonic_to_seed(_ELECTRUM_SEED, '')
        ks_root = keystore.BIP32_KeyStore({})
        ks_root.add_xprv_from_seed(bip32_seed, 'standard', 'm/')

        scan_pubkey_standard = w.derive_pubkeys_rpa(0, 0)
        scan_pubkey_root = ks_root.derive_pubkey(0, 0)

        self.assertNotEqual(
            scan_pubkey_standard, scan_pubkey_root,
            "Standard_Wallet scan pubkey must differ from the root-derived pubkey "
            "(legacy RpaWallet uses root derivation; Standard_Wallet uses m/44'/145'/8')"
        )

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
