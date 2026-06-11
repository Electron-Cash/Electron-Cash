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


def _make_wallet_from_master_key(master_key):
    """Simulates restoring a wallet on another computer from an exported
    xprv (or xpub, for a watching-only wallet)."""
    ks = keystore.from_master_key(master_key)
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', 1)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    return w


def _test_wif():
    # deterministic test key: bytes 1..32 (valid secp256k1 scalar)
    return bitcoin.serialize_privkey(bytes(range(1, 33)), True, 'p2pkh')


# Known-good paycode for _ELECTRUM_SEED (scan/spend keys at account-node
# chain 3). Pins the derivation against accidental changes.
_GOLDEN_PAYCODE = ('paycode:qygqxukkpq33mkzs0529rs7390xzg8vclqqx39ddn2pyzlk5qh95w'
                   '2ydq07zz3z83jppwex4f57ltw57g6plg2eg5cqf8yf7mxhgynxxpfdm5qqq'
                   'qqqqs8f5m6v9')


class TestRpaStandardWallet(unittest.TestCase):

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_electrum_seed(self, _mock_write):
        """enable_rpa() needs no seed access and no password."""
        w = _make_electrum_wallet()
        self.assertFalse(w.is_rpa_enabled())

        w.enable_rpa()

        self.assertTrue(w.is_rpa_enabled())
        self.assertTrue(w.get_receiving_paycode().startswith('paycode:'))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_bip39_seed(self, _mock_write):
        w = _make_bip39_wallet()
        self.assertFalse(w.is_rpa_enabled())

        w.enable_rpa()

        self.assertTrue(w.is_rpa_enabled())
        self.assertTrue(w.get_receiving_paycode().startswith('paycode:'))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_paycode_golden(self, _mock_write):
        """Paycodes must be bit-identical to the aux-keystore implementation
        (captured before the refactor) — wallets that enabled RPA earlier keep
        their paycode."""
        w = _make_electrum_wallet()
        w.enable_rpa()
        self.assertEqual(w.get_receiving_paycode(), _GOLDEN_PAYCODE)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_paycode_uses_chain_3(self, _mock_write):
        """RPA scan key is at {keystore.derivation}/3/0, distinct from {keystore.derivation}/0/0."""
        w = _make_electrum_wallet()
        w.enable_rpa()

        scan_pubkey = w.derive_pubkeys_rpa(3, 0)
        spend_pubkey = w.derive_pubkeys_rpa(3, 1)
        # {keystore.derivation}/0/0 is the first normal receive key
        first_receive_key = w.keystore.derive_pubkey(0, 0)

        self.assertNotEqual(
            scan_pubkey, first_receive_key,
            "RPA scan key ({keystore.derivation}/3/0) must differ from first receive key ({keystore.derivation}/0/0)"
        )
        self.assertNotEqual(scan_pubkey, spend_pubkey)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_change_addresses_not_poisoned_by_paycode_derivation(self, _mock_write):
        """The main keystore is now shared between HD chains and RPA chain 3:
        deriving the paycode must not poison the keystore's change-address
        cache (Xpub.derive_pubkey treats the chain index as a boolean)."""
        w = _make_electrum_wallet()
        w.enable_rpa()
        fresh = _make_electrum_wallet()
        expected_change_key = fresh.keystore.derive_pubkey(1, 0)

        w.get_receiving_paycode()  # derives chain-3 keys from the shared keystore

        self.assertEqual(w.keystore.derive_pubkey(1, 0), expected_change_key)
        self.assertNotEqual(w.derive_pubkeys_rpa(3, 0), expected_change_key)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_can_enable_rpa_matrix(self, _mock_write):
        """Seed and xprv wallets can enable RPA; watching-only cannot."""
        w_seed = _make_electrum_wallet()
        self.assertTrue(w_seed.can_enable_rpa())

        xprv = w_seed.keystore.get_master_private_key(None)
        self.assertTrue(_make_wallet_from_master_key(xprv).can_enable_rpa())

        w_watch = _make_wallet_from_master_key(w_seed.keystore.xpub)
        self.assertFalse(w_watch.can_enable_rpa())
        with self.assertRaises(RuntimeError):
            w_watch.enable_rpa()

        # Abstract_Wallet default is False so GUIs may call unconditionally
        self.assertFalse(wallet.Abstract_Wallet.can_enable_rpa(w_seed))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_enable_rpa_needs_no_password(self, _mock_write):
        """Enabling RPA and showing the paycode are pubkey-only operations;
        only scanning/extraction needs the password."""
        w = _make_electrum_wallet()
        w.update_password(None, 'topsecret')
        w.enable_rpa()
        self.assertTrue(w.is_rpa_enabled())
        self.assertTrue(w.get_receiving_paycode().startswith('paycode:'))
        # Scanning/extraction still requires the password. Note the keystore
        # raises InvalidXKey (a BaseException!) for an undecrypted xprv --
        # pre-existing BIP32_KeyStore behavior, identical to the old aux path.
        with self.assertRaises((InvalidPassword, bitcoin.InvalidXKey)):
            w.export_private_key_from_index((3, 0), None)
        self.assertTrue(w.export_private_key_from_index((3, 0), 'topsecret'))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_same_paycode_after_xprv_restore(self, _mock_write):
        """Export the xprv, restore it on 'another computer', enable RPA:
        the paycode must be identical."""
        a = _make_electrum_wallet()
        a.enable_rpa()

        xprv = a.keystore.get_master_private_key(None)
        b = _make_wallet_from_master_key(xprv)
        b.enable_rpa()

        self.assertEqual(b.get_receiving_paycode(), a.get_receiving_paycode())
        self.assertEqual(b.derive_pubkeys_rpa(3, 0), a.derive_pubkeys_rpa(3, 0))


    @mock.patch.object(storage.WalletStorage, '_write')
    def test_get_addresses_includes_rpa_imported(self, _mock_write):
        """get_addresses() returns HD addresses plus any RPA-imported addresses."""
        w = _make_electrum_wallet()
        w.enable_rpa()

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
        w.enable_rpa()

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
    w.enable_rpa()
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


class TestRpaImportedAddressSource(unittest.TestCase):
    """get_rpa_imported_addresses is the only address source for paycode keys.
    The HD lists must stay pure: synchronize_sequence's gap-limit logic creates
    a new HD address whenever the trailing entries are used, and RPA-imported
    addresses are always used by construction."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_empty_without_rpa(self, _mock_write):
        w = _make_electrum_wallet()
        self.assertEqual(w.get_rpa_imported_addresses(), [])
        # The Abstract_Wallet default is [] so GUIs may call unconditionally
        self.assertEqual(wallet.Abstract_Wallet.get_rpa_imported_addresses(w), [])

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_lists_imported_key(self, _mock_write):
        w = _make_electrum_wallet()
        w.enable_rpa()
        w.import_rpa_private_key(_test_wif(), None)
        expected = PublicKey.from_WIF_privkey(_test_wif()).address
        self.assertEqual(w.get_rpa_imported_addresses(), [expected])

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_rpa_imported_not_in_hd_address_lists(self, _mock_write):
        """Pins the gap-limit invariant: imported addresses are reachable via
        get_addresses() but never via the HD receiving/change lists."""
        w = _make_electrum_wallet()
        w.enable_rpa()
        w.import_rpa_private_key(_test_wif(), None)
        addr = w.get_rpa_imported_addresses()[0]
        self.assertIn(addr, w.get_addresses())
        self.assertNotIn(addr, w.get_receiving_addresses())
        self.assertNotIn(addr, w.get_change_addresses())

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_synchronize_stable_after_rpa_import(self, _mock_write):
        """Regression test for runaway HD address derivation: a funded (i.e.
        used) RPA-imported address must not make synchronize() grow the HD
        receiving list."""
        from .test_rpa_paycode_send import _fund_wallet
        w = _make_electrum_wallet()
        w.enable_rpa()
        w.import_rpa_private_key(_test_wif(), None)
        _fund_wallet(w, w.get_rpa_imported_addresses()[0])

        n_before = len(w.get_receiving_addresses())
        for _i in range(3):
            w.synchronize()
        self.assertEqual(len(w.get_receiving_addresses()), n_before)


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
        w.enable_rpa()
        self.assertIsInstance(w.rpa_height, int)
