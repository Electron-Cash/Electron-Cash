import queue
import unittest
from unittest import mock

from .. import rpa
from .. import storage
from ..rpa.rpa_manager import RpaManager

from .test_rpa_manager_lifecycle import FakeNetwork
from .test_rpa_standard_wallet import _make_electrum_wallet


def _make_rpa_wallet(password=None):
    w = _make_electrum_wallet()
    w.enable_rpa()
    if password is not None:
        w.update_password(None, password)
        # update_password caches the session password; clear it to simulate a
        # freshly opened wallet, which is the state the prompt runs in.
        w.rpa_pwd = None
    return w


class RecordingFakeNetwork(FakeNetwork):

    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, requests, callback):
        self.sent.append(requests)


class TestAcquireRpaPassword(unittest.TestCase):
    """Cancel pauses scanning for the session, a typo re-prompts; the window
    must never be torn down (the helper never raises and never loops on
    non-password errors)."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_no_prompt_without_password(self, _mock_write):
        w = _make_rpa_wallet()
        request_password = mock.Mock()
        self.assertTrue(rpa.acquire_rpa_password(w, request_password, mock.Mock()))
        request_password.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_no_prompt_when_rpa_disabled(self, _mock_write):
        w = _make_electrum_wallet()
        w.update_password(None, 'topsecret')
        request_password = mock.Mock()
        self.assertTrue(rpa.acquire_rpa_password(w, request_password, mock.Mock()))
        request_password.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_cancel_pauses_session(self, _mock_write):
        """Direct regression test for the force-close on cancel."""
        w = _make_rpa_wallet('topsecret')
        show_error = mock.Mock()
        result = rpa.acquire_rpa_password(w, lambda: None, show_error)
        self.assertFalse(result)
        self.assertIsNone(w.rpa_pwd)
        show_error.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_wrong_then_correct_password_retries(self, _mock_write):
        w = _make_rpa_wallet('topsecret')
        request_password = mock.Mock(side_effect=['wrong', 'topsecret'])
        show_error = mock.Mock()
        result = rpa.acquire_rpa_password(w, request_password, show_error)
        self.assertTrue(result)
        self.assertEqual(w.rpa_pwd, 'topsecret')
        self.assertEqual(request_password.call_count, 2)
        self.assertEqual(show_error.call_count, 1)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_correct_password_first_try(self, _mock_write):
        w = _make_rpa_wallet('topsecret')
        show_error = mock.Mock()
        result = rpa.acquire_rpa_password(w, lambda: 'topsecret', show_error)
        self.assertTrue(result)
        self.assertEqual(w.rpa_pwd, 'topsecret')
        show_error.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_cached_password_used_without_prompt(self, _mock_write):
        """A valid cached password (e.g. from wallet unlock at startup) is used
        silently -- the user is never prompted."""
        w = _make_rpa_wallet('topsecret')
        request_password = mock.Mock()
        show_error = mock.Mock()
        result = rpa.acquire_rpa_password(w, request_password, show_error,
                                          cached_password='topsecret')
        self.assertTrue(result)
        self.assertEqual(w.rpa_pwd, 'topsecret')
        request_password.assert_not_called()
        show_error.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_no_cached_password_falls_back_to_prompt(self, _mock_write):
        """cached_password=None (nothing cached) prompts as usual."""
        w = _make_rpa_wallet('topsecret')
        request_password = mock.Mock(return_value='topsecret')
        result = rpa.acquire_rpa_password(w, request_password, mock.Mock(),
                                          cached_password=None)
        self.assertTrue(result)
        self.assertEqual(w.rpa_pwd, 'topsecret')
        request_password.assert_called_once()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_invalid_cached_password_falls_back_to_prompt(self, _mock_write):
        """A stale/invalid cached password must not loop or raise: fall back to
        the dialog instead."""
        w = _make_rpa_wallet('topsecret')
        request_password = mock.Mock(return_value='topsecret')
        show_error = mock.Mock()
        result = rpa.acquire_rpa_password(w, request_password, show_error,
                                          cached_password='wrong')
        self.assertTrue(result)
        self.assertEqual(w.rpa_pwd, 'topsecret')
        request_password.assert_called_once()
        show_error.assert_not_called()

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_unexpected_error_gives_up_cleanly(self, _mock_write):
        """Non-password errors must not retry-loop forever (or close anything)."""
        w = _make_rpa_wallet('topsecret')
        request_password = mock.Mock(return_value='topsecret')
        show_error = mock.Mock()
        with mock.patch.object(type(w), 'check_password',
                               side_effect=RuntimeError('boom')):
            result = rpa.acquire_rpa_password(w, request_password, show_error)
        self.assertFalse(result)
        self.assertIsNone(w.rpa_pwd)
        self.assertEqual(request_password.call_count, 1)
        self.assertEqual(show_error.call_count, 1)


class TestRpaManagerPausedWithoutPassword(unittest.TestCase):
    """While rpa_pwd is unavailable the manager must neither fetch new work
    nor consume queued work."""

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_phase4_preserves_queue_without_password(self, _mock_write):
        w = _make_rpa_wallet('topsecret')
        self.assertIsNone(w.rpa_pwd)
        mgr = RpaManager(w, FakeNetwork())
        sentinel = ('00' * 32, 800000)
        mgr.rpa_q_rawtx.put(sentinel)

        mgr.rpa_phase_4()

        self.assertEqual(mgr.rpa_q_rawtx.get_nowait(), sentinel)
        self.assertEqual(len(w.keystore_rpa_imported.keypairs), 0)

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_mempool_phase_skipped_without_password(self, _mock_write):
        w = _make_rpa_wallet('topsecret')
        net = RecordingFakeNetwork()
        mgr = RpaManager(w, net)

        mgr.rpa_phase_1_mempool(polling=False)
        self.assertEqual(net.sent, [])

        w.rpa_pwd = 'topsecret'
        mgr.rpa_phase_1_mempool(polling=False)
        self.assertEqual(len(net.sent), 1)
