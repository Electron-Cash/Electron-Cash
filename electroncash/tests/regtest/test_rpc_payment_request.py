from .util import poll_for_answer, get_bitcoind_rpc_connection, EC_DAEMON_RPC_URL, docker_compose_file, fulcrum_service, SUPPORTED_PLATFORM, switch_wallet

import pytest
from typing import Any

from jsonrpcclient import request

@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_addrequest(fulcrum_service: Any) -> None:
    """ Verify the `addrequest` RPC by creating a request, pay it and remove it """

    bitcoind = get_bitcoind_rpc_connection()
    switch_wallet("test_misc")
    bitcoind.generate(1)

    result = poll_for_answer(EC_DAEMON_RPC_URL, request('listrequests'))
    assert len(result) == 0

    result = poll_for_answer(EC_DAEMON_RPC_URL, request('addrequest', params={"amount": 0.00001}))
    assert result['status'] == 'Pending'
    assert result['amount'] == 1000
    addr = result['address']

    bitcoind.sendtoaddress(addr, 0.00001)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('listrequests'), expected_answer=('[0].status', 'Unconfirmed'))
    assert len(result) == 1
    assert result[0]['status'] == 'Unconfirmed'

    bitcoind.generate(1)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('listrequests'), expected_answer=('[0].status', 'Paid'))
    assert result[0]['status'] == 'Paid'

    poll_for_answer(EC_DAEMON_RPC_URL, request('clearrequests'))
    result = poll_for_answer(EC_DAEMON_RPC_URL, request('listrequests'))
    assert len(result) == 0
    switch_wallet("test_other")