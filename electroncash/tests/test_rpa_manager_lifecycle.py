import unittest
from unittest import mock

from .. import keystore
from .. import storage
from .. import wallet
from ..wallet import Abstract_Wallet
from ..rpa.rpa_manager import RpaManager


_ELECTRUM_SEED = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'


class FakeNetwork:
    """Minimal network stub sufficient for start_threads / stop_threads."""

    def __init__(self):
        self.jobs = []

    def blockchain(self):
        return mock.MagicMock()

    def add_jobs(self, jobs):
        self.jobs.extend(jobs)

    def remove_jobs(self, jobs):
        for job in jobs:
            if job in self.jobs:
                self.jobs.remove(job)

    def get_server_height(self):
        return 0

    def register_callback(self, cb, events):
        pass

    def unregister_callback(self, cb):
        pass

    def trigger_callback(self, event, *args):
        pass

    def send(self, requests, callback):
        pass

    def get_local_height(self):
        return 0

    def is_connected(self):
        return False


def _make_rpa_enabled_wallet():
    ks = keystore.from_seed(_ELECTRUM_SEED, '', False)
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', 1)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    w.enable_rpa(None)
    return w


def _make_rpa_disabled_wallet():
    ks = keystore.from_seed(_ELECTRUM_SEED, '', False)
    store = storage.WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', 1)
    w = wallet.Standard_Wallet(store)
    w.synchronize()
    return w


class TestRpaManagerLifecycle(unittest.TestCase):

    @mock.patch.object(storage.WalletStorage, '_write')
    @mock.patch.object(Abstract_Wallet, 'start_pruned_txo_cleaner_thread')
    @mock.patch('electroncash.wallet.Synchronizer')
    @mock.patch('electroncash.wallet.SPV')
    def test_start_threads_adds_rpa_manager_when_enabled(
            self, _mock_spv, _mock_sync, _mock_prune, _mock_write):
        """start_threads creates an RpaManager when RPA is enabled."""
        w = _make_rpa_enabled_wallet()
        net = FakeNetwork()

        w.start_threads(net)
        try:
            self.assertIsNotNone(w.rpa_manager)
            self.assertIsInstance(w.rpa_manager, RpaManager)
            self.assertIn(w.rpa_manager, net.jobs)
        finally:
            w.stop_threads()

    @mock.patch.object(storage.WalletStorage, '_write')
    @mock.patch.object(Abstract_Wallet, 'start_pruned_txo_cleaner_thread')
    @mock.patch('electroncash.wallet.Synchronizer')
    @mock.patch('electroncash.wallet.SPV')
    def test_start_threads_no_rpa_manager_when_disabled(
            self, _mock_spv, _mock_sync, _mock_prune, _mock_write):
        """start_threads leaves rpa_manager as None when RPA is not enabled."""
        w = _make_rpa_disabled_wallet()
        net = FakeNetwork()

        w.start_threads(net)
        try:
            self.assertIsNone(w.rpa_manager)
            self.assertFalse(any(isinstance(j, RpaManager) for j in net.jobs))
        finally:
            w.stop_threads()

    @mock.patch.object(storage.WalletStorage, '_write')
    @mock.patch.object(Abstract_Wallet, 'start_pruned_txo_cleaner_thread')
    @mock.patch('electroncash.wallet.Synchronizer')
    @mock.patch('electroncash.wallet.SPV')
    def test_stop_threads_removes_rpa_manager(
            self, _mock_spv, _mock_sync, _mock_prune, _mock_write):
        """stop_threads removes the RpaManager from network jobs and clears it."""
        w = _make_rpa_enabled_wallet()
        net = FakeNetwork()

        w.start_threads(net)
        self.assertIsNotNone(w.rpa_manager)

        w.stop_threads()

        self.assertIsNone(w.rpa_manager)
        self.assertFalse(any(isinstance(j, RpaManager) for j in net.jobs))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_start_rpa_manager_mid_session(self, _mock_write):
        """start_rpa_manager() can wire up an RpaManager after start_threads."""
        w = _make_rpa_enabled_wallet()
        net = FakeNetwork()
        w.network = net
        w.rpa_manager = None

        w.start_rpa_manager()

        self.assertIsNotNone(w.rpa_manager)
        self.assertIsInstance(w.rpa_manager, RpaManager)
        self.assertIn(w.rpa_manager, net.jobs)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_stop_rpa_manager_mid_session(self, _mock_write):
        """stop_rpa_manager() removes an in-flight RpaManager without affecting network."""
        w = _make_rpa_enabled_wallet()
        net = FakeNetwork()
        w.network = net
        w.rpa_manager = None

        w.start_rpa_manager()
        self.assertIsNotNone(w.rpa_manager)

        w.stop_rpa_manager()

        self.assertIsNone(w.rpa_manager)
        self.assertFalse(any(isinstance(j, RpaManager) for j in net.jobs))


class ConnectedFakeNetwork(FakeNetwork):
    """rebuild_history refuses to run without a connected server."""

    def is_connected(self):
        return True


class TestRebuildHistoryResetsRpaHeight(unittest.TestCase):

    @mock.patch.object(storage.WalletStorage, '_write')
    @mock.patch.object(Abstract_Wallet, 'start_pruned_txo_cleaner_thread')
    @mock.patch('electroncash.wallet.Synchronizer')
    @mock.patch('electroncash.wallet.SPV')
    def test_rebuild_history_resets_rpa_height(
            self, _mock_spv, _mock_sync, _mock_prune, _mock_write):
        """Wallet > Rebuild History must restart the RPA scan from scratch."""
        w = _make_rpa_enabled_wallet()
        net = ConnectedFakeNetwork()
        w.start_threads(net)
        try:
            w.rpa_height = 899999
            self.assertEqual(w.storage.get('rpa_height'), 899999)

            w.rebuild_history()

            self.assertIsNone(w.storage.get('rpa_height'))
            self.assertIsNotNone(w.rpa_manager)
            self.assertIn(w.rpa_manager, net.jobs)
        finally:
            w.stop_threads()
