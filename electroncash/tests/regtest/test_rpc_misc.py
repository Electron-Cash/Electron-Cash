from .util import poll_for_answer, get_bitcoind_rpc_connection, EC_DAEMON_RPC_URL, docker_compose_file, fulcrum_service, SUPPORTED_PLATFORM, recreate_wallet, switch_wallet

import pytest
from typing import Any

from jsonrpcclient import request

@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getunusedaddress(fulcrum_service: Any) -> None:
    """ Verify the `getunusedaddress` RPC """
    address = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))

    # The daemon does not return a prefix.
    # Check that the length is 42 and starts with 'q'
    assert len(address) == 42
    assert address[0] == 'q'
    same_address = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    assert address == same_address

@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getservers(fulcrum_service: Any) -> None:
    """ Verify the `getservers` RPC """
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getservers'))

    # Only one server in this setup
    assert len(result) == 1

@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_balance(fulcrum_service: Any) -> None:
    def _strip_decimal(amount: str):
        if amount[-2:] == ".0":
            return amount[:-2]
        return amount

    """ Verify the `getbalance` RPC """
    recreate_wallet()
    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))

    bitcoind = get_bitcoind_rpc_connection()
    switch_wallet("test_misc")

    blockhash = bitcoind.generatetoaddress(1, addr)
    coinbase_amount = _strip_decimal(str(float(bitcoind.getblockstats(blockhash[0])['subsidy'])))
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getbalance'), expected_answer=('unmatured', coinbase_amount))
    assert result['unmatured'] == coinbase_amount

    bitcoind.sendtoaddress(addr, 10)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getbalance'), expected_answer=('unconfirmed', '10'))
    assert result['unmatured'] == coinbase_amount and result['unconfirmed'] == '10'

    bitcoind.generate(1)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getbalance'), expected_answer=('confirmed', '10'))
    assert result['unmatured'] == coinbase_amount and result['confirmed'] == '10'

    bitcoind.generate(97)
    bitcoind.sendtoaddress(addr, 10)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getbalance'), expected_answer=('unconfirmed', '10'))
    assert result['unmatured'] == coinbase_amount and result['confirmed'] == '10' and result['unconfirmed'] == '10'

    bitcoind.generate(1)
    coinbase_amount_plus_20 = _strip_decimal(str(float(coinbase_amount)+20))
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('getbalance'), expected_answer=('confirmed', coinbase_amount_plus_20))
    assert result['confirmed'] == coinbase_amount_plus_20
    switch_wallet("test_other")
