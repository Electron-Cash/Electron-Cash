"""
Tests for transparent token-UTXO spending:
- Token UTXOs with satoshis above dust are included in normal coin selection.
- After selection, mandatory token dust outputs go to change addresses (not the
  original token UTXO address).
- The balance function no longer separates token-locked satoshis.
"""
import unittest
from unittest.mock import Mock, patch, call

from ..address import Address
from .. import token
from .. import wallet
from ..bitcoin import TYPE_ADDRESS
from ..wallet import calc_dust

# ---------------------------------------------------------------------------
# Fixed test addresses (P2PKH, derived deterministically from simple seeds)
# ---------------------------------------------------------------------------
SENDER_ADDR    = Address.from_string("bitcoincash:qpev6m5yytzq07mdpxrfpugnpd776lkz7usne8zmp4")
TOKEN_ADDR     = Address.from_string("bitcoincash:qp6cw7a5r5unkhacg4wwvrkd3hdqq8gxxy6q84hhrz")
CHANGE_ADDR    = Address.from_string("bitcoincash:qpjg4fw908anpuu27azdjltwepqv02gjwutdun5qs3")
RECIPIENT_ADDR = Address.from_string("bitcoincash:qz05ld508cw6eq3q97d2tqwwpwl37aja7qf90cjur5")

TOKEN_DATA = token.OutputData(id=b'\xaa' * 32, amount=1000)
# Pre-compute the expected dust for TOKEN_DATA at TOKEN_ADDR once.
TOKEN_DUST = calc_dust(TOKEN_ADDR, TOKEN_DATA)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_coin(addr, value, txhash=None, n=0, token_data=None):
    """Return a minimal UTXO dict pre-populated with signing metadata."""
    return {
        'address': addr,
        'value': value,
        'prevout_hash': txhash or ('aa' * 32),
        'prevout_n': n,
        'height': 700_000,
        'coinbase': False,
        'is_frozen_coin': False,
        'slp_token': None,
        'token_data': token_data,
        # Signing fields — kept here so add_input_info mock can be a no-op
        'type': 'p2pkh',
        'x_pubkeys': ['ff' + '00' * 38],
        'signatures': [None],
        'num_sig': 1,
        'sequence': 0xffffffff,
    }


def _populate_input(inp):
    """Side-effect for mock add_input_info: fill signing fields in-place."""
    inp.setdefault('type', 'p2pkh')
    inp.setdefault('x_pubkeys', ['ff' + '00' * 38])
    inp.setdefault('signatures', [None])
    inp.setdefault('num_sig', 1)
    inp.setdefault('sequence', 0xffffffff)


def _make_mock_wallet(change_addrs=None):
    """Return a Mock(spec=Abstract_Wallet) wired up for make_unsigned_transaction."""
    mock_w = Mock(spec=wallet.Abstract_Wallet)
    mock_w.is_schnorr_enabled.return_value = False
    mock_w.use_change = True
    mock_w.multiple_change = False
    mock_w.max_change_outputs = 1
    mock_w.gap_limit_for_change = 20
    mock_w.add_input_info.side_effect = _populate_input
    mock_w.dust_threshold.return_value = 546
    mock_w.get_default_change_addresses.return_value = list(change_addrs or [CHANGE_ADDR])
    mock_w.is_mine.return_value = True
    mock_w.get_preferred_change_addresses.return_value = [CHANGE_ADDR]
    mock_w.get_num_tx.return_value = 0
    mock_w.get_local_height.return_value = 700_000
    return mock_w


class TestTokenUtxoSpending(unittest.TestCase):
    """Integration-level tests for make_unsigned_transaction with token UTXOs."""

    def setUp(self):
        # Token UTXO has TOKEN_DUST + 20_000 sat, so 20_000 sat net contribution to the
        # coin chooser.  The large surplus ensures the token singleton always covers any
        # reasonable output + fee combination used in the tests below.
        self.token_utxo = _make_coin(TOKEN_ADDR, TOKEN_DUST + 20_000, 'bb' * 32, 0, TOKEN_DATA)

    def _call(self, mock_w, inputs, outputs, fixed_fee=2_000, token_datas=None):
        """Invoke the real make_unsigned_transaction with run_hook patched out."""
        with patch('electroncash.wallet.run_hook', return_value=None):
            return wallet.Abstract_Wallet.make_unsigned_transaction(
                mock_w, inputs, outputs, Mock(),
                fixed_fee=fixed_fee, bip69_sort=False, token_datas=token_datas,
            )

    def _token_outputs(self, tx):
        """Return [(output_tuple, token_data)] for all outputs that carry a token."""
        return [
            (out, td)
            for out, td in zip(tx.outputs(), tx.token_datas())
            if td is not None
        ]

    # ------------------------------------------------------------------
    # 1. A token UTXO at exactly the dust threshold is added to the pool
    #    with net value 0.  When a sufficient non-token input exists,
    #    strip_unneeded removes the zero-value bucket and it is not spent.
    # ------------------------------------------------------------------
    def test_token_utxo_at_dust_threshold_not_spent_when_non_token_sufficient(self):
        # value == dust → net contribution = 0 → coin chooser strips it
        # when the non-token input alone covers the amount.
        at_dust_utxo = _make_coin(TOKEN_ADDR, TOKEN_DUST, 'bb' * 32, 0, TOKEN_DATA)
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 100_000, 'aa' * 32, 0), at_dust_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 10_000)]

        tx = self._call(mock_w, inputs, outputs)

        self.assertFalse(any(inp.get('token_data') for inp in tx.inputs()),
                         "Zero-net token UTXO must be stripped when non-token input suffices")
        self.assertEqual([], self._token_outputs(tx),
                         "No token dust outputs expected")

    # ------------------------------------------------------------------
    # 2. Token UTXO IS selected when non-token inputs are insufficient
    # ------------------------------------------------------------------
    def test_token_utxo_selected_when_non_token_insufficient(self):
        # Non-token input alone can't cover output (5000) + fee (2000).
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 500, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 5_000)]

        tx = self._call(mock_w, inputs, outputs)

        tok_inputs = [inp for inp in tx.inputs() if inp.get('token_data')]
        self.assertEqual(len(tok_inputs), 1,
                         "Exactly one token input expected")
        self.assertEqual(tok_inputs[0]['prevout_hash'], 'bb' * 32,
                         "The token UTXO from the pool should be selected")

    # ------------------------------------------------------------------
    # 3. Token dust output goes to a change address, not the original address
    # ------------------------------------------------------------------
    def test_non_max_token_dust_output_address_is_change_address(self):
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 500, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 5_000)]

        tx = self._call(mock_w, inputs, outputs)

        tok_outs = self._token_outputs(tx)
        self.assertEqual(len(tok_outs), 1)
        _, addr, _ = tok_outs[0][0]
        self.assertNotEqual(addr, TOKEN_ADDR,
                            "Token output must NOT go back to the original token UTXO address")
        self.assertEqual(addr, CHANGE_ADDR,
                         "Token output must go to a wallet change address")

    # ------------------------------------------------------------------
    # 4. Token dust output amount equals calc_dust exactly
    # ------------------------------------------------------------------
    def test_non_max_token_dust_output_amount_equals_calc_dust(self):
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 500, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 5_000)]

        tx = self._call(mock_w, inputs, outputs)

        tok_outs = self._token_outputs(tx)
        self.assertEqual(len(tok_outs), 1)
        _, _, amount = tok_outs[0][0]
        self.assertEqual(amount, TOKEN_DUST,
                         "Token dust output amount must equal calc_dust(TOKEN_ADDR, TOKEN_DATA)")

    # ------------------------------------------------------------------
    # 5. MAX path: token UTXOs are auto-included as inputs
    # ------------------------------------------------------------------
    def test_max_path_includes_token_utxos(self):
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 10_000, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, '!')]

        tx = self._call(mock_w, inputs, outputs)

        tok_inputs = [inp for inp in tx.inputs() if inp.get('token_data')]
        self.assertEqual(len(tok_inputs), 1)
        self.assertEqual(tok_inputs[0]['prevout_hash'], 'bb' * 32)

    # ------------------------------------------------------------------
    # 6. MAX path: token dust output goes to change address
    # ------------------------------------------------------------------
    def test_max_path_token_dust_output_address_is_change_address(self):
        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, 10_000, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, '!')]

        tx = self._call(mock_w, inputs, outputs)

        tok_outs = self._token_outputs(tx)
        self.assertEqual(len(tok_outs), 1)
        _, addr, _ = tok_outs[0][0]
        self.assertNotEqual(addr, TOKEN_ADDR,
                            "Token output must NOT go back to the original token UTXO address")
        self.assertEqual(addr, CHANGE_ADDR,
                         "Token output must go to a wallet change address")

    # ------------------------------------------------------------------
    # 7. MAX path: recipient receives all BCH minus token dust and fee
    # ------------------------------------------------------------------
    def test_max_path_recipient_amount_is_all_minus_dust_and_fee(self):
        NON_TOK_VALUE = 10_000
        TOK_VALUE = TOKEN_DUST + 20_000  # matches setUp token_utxo
        FIXED_FEE = 1_000

        mock_w = _make_mock_wallet()
        inputs = [_make_coin(SENDER_ADDR, NON_TOK_VALUE, 'aa' * 32, 0), self.token_utxo]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, '!')]

        tx = self._call(mock_w, inputs, outputs, fixed_fee=FIXED_FEE)

        recipient_outs = [
            out for out, td in zip(tx.outputs(), tx.token_datas())
            if td is None and out[1] == RECIPIENT_ADDR
        ]
        self.assertEqual(len(recipient_outs), 1)
        _, _, amount = recipient_outs[0]
        # sendable = NON_TOK_VALUE + TOK_VALUE (full token UTXO value)
        # token dust output consumes TOKEN_DUST; recipient gets the rest minus fee
        expected = NON_TOK_VALUE + TOK_VALUE - TOKEN_DUST - FIXED_FEE
        self.assertEqual(amount, expected)

    # ------------------------------------------------------------------
    # 8. When caller_handles_tokens=True (token_datas has non-None entries),
    #    token inputs in the inputs list are NOT auto-transformed — they flow
    #    through as-is and no extra token dust outputs are injected.
    # ------------------------------------------------------------------
    def test_caller_handles_tokens_skips_auto_transform(self):
        # Explicit token send: caller owns the token_datas list.
        # The token UTXO is passed at full value (no net-value subtract).
        explicit_tok_input = _make_coin(TOKEN_ADDR, TOKEN_DUST + 3_000, 'bb' * 32, 0, TOKEN_DATA)
        mock_w = _make_mock_wallet()
        inputs = [
            _make_coin(SENDER_ADDR, 10_000, 'aa' * 32, 0),
            explicit_tok_input,
        ]
        # Mimic what make_token_send_tx provides: one None per non-token output,
        # one non-None for each token input/output the caller manages.
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 5_000),
                   (TYPE_ADDRESS, CHANGE_ADDR, TOKEN_DUST)]
        caller_token_datas = [None, TOKEN_DATA]

        tx = self._call(mock_w, inputs, outputs, token_datas=caller_token_datas)

        # Auto-transform must NOT have run: no extra injected token outputs
        # beyond what the caller put in outputs.
        tok_outs = self._token_outputs(tx)
        self.assertEqual(len(tok_outs), 1,
                         "Only the caller-supplied token output should exist; no auto-injected ones")
        _, addr, _ = tok_outs[0][0]
        self.assertEqual(addr, CHANGE_ADDR,
                         "The single token output should be exactly what the caller specified")

    # ------------------------------------------------------------------
    # 9. get_addr_balance: tok_locked (4th element) is always zero
    # ------------------------------------------------------------------
    def test_get_addr_balance_tok_locked_is_zero(self):
        mock_w = Mock(spec=wallet.Abstract_Wallet)
        mock_w.get_local_height.return_value = 700_000
        mock_w._addr_bal_cache = {}
        mock_w.frozen_coins = set()
        mock_w.frozen_coins_tmp = set()

        # Simulate one received token UTXO worth 10 000 sat, confirmed
        txo_key = ('aabbcc' * 10 + 'aa', 0)  # dummy (txhash, n) key
        received = {txo_key: (700_000, 10_000, False, TOKEN_DATA)}
        sent = {}
        mock_w.get_addr_io.return_value = (received, sent)

        c, u, x, tok_locked = wallet.Abstract_Wallet.get_addr_balance(
            mock_w, TOKEN_ADDR, tokens=True
        )

        self.assertEqual(tok_locked, 0,
                         "tok_locked must be 0; token sat are counted as regular balance")
        self.assertEqual(c, 10_000,
                         "Full UTXO value must be counted in confirmed balance")

    # ------------------------------------------------------------------
    # 10. Privacy: when two token UTXOs share the same address and the
    #     one with excess BCH is selected, the dust-only UTXO at that
    #     same address must be spent together with it.
    #
    #     CoinChooserPrivacy groups coins by address into buckets, so
    #     spending any coin from an address spends all coins from that
    #     address.  Both UTXOs must be in the pool for this to work —
    #     including the dust-value one (net contribution = 0).
    # ------------------------------------------------------------------
    def test_same_address_dust_utxo_spent_together_with_above_dust_utxo(self):
        tok_x = token.OutputData(id=b'\x11' * 32, amount=100)
        tok_y = token.OutputData(id=b'\x22' * 32, amount=200)
        dust_x = calc_dust(TOKEN_ADDR, tok_x)
        dust_y = calc_dust(TOKEN_ADDR, tok_y)

        utxo1 = _make_coin(TOKEN_ADDR, dust_x + 20_000, 'b1' * 32, 0, tok_x)  # excess BCH
        utxo2 = _make_coin(TOKEN_ADDR, dust_y,           'b2' * 32, 1, tok_y)  # dust only

        mock_w = _make_mock_wallet()
        # Tiny non-token input keeps make_unsigned_transaction from raising
        # NotEnoughFunds on the empty-inputs check, but is insufficient alone.
        inputs = [_make_coin(SENDER_ADDR, 200, 'aa' * 32, 0), utxo1, utxo2]
        outputs = [(TYPE_ADDRESS, RECIPIENT_ADDR, 10_000)]

        tx = self._call(mock_w, inputs, outputs)

        tok_hashes = {inp['prevout_hash'] for inp in tx.inputs() if inp.get('token_data')}
        self.assertIn('b1' * 32, tok_hashes,
                      "UTXO1 (token X, excess BCH) must be spent")
        self.assertIn('b2' * 32, tok_hashes,
                      "UTXO2 (token Y, dust only, same address) must be spent together with UTXO1")
