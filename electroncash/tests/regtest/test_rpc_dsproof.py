from .util import poll_for_answer, get_bitcoind_rpc_connection, recreate_wallet, EC_DAEMON_RPC_URL, docker_compose_file, fulcrum_service, SUPPORTED_PLATFORM
import pytest
from typing import Any
from bitcoinrpc.authproxy import JSONRPCException

from jsonrpcclient import request

DUMMY_ADDRESS = 'qpmlzhu6zzqn6d06um3h2k6lmq4xqckawsf97vpzvw'

@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getdspstatus_unconfirmed_to_confirmed(fulcrum_service: Any) -> None:
    """ Verify the `getdspstatus` RPC by checking an unconfirmed and confirmed tx """
    bitcoind = get_bitcoind_rpc_connection()
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)
    bitcoind.sendtoaddress(bitcoind.getnewaddress(), bitcoind.getbalance(), "", "", True)
    bitcoind.generate(1)

    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    txid = bitcoind.sendtoaddress(addr, 10)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 4))
    bitcoind.generate(1)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 2))


@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getdspstatus_dsproof_exists(fulcrum_service: Any) -> None:
    """ Verify the `getdspstatus` RPC by checking status on an existing dsp """
    bitcoind = get_bitcoind_rpc_connection()
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)
    bitcoind_addr = bitcoind.getnewaddress()
    bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)

    consolidate_txid = bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    bitcoind.generatetoaddress(1, DUMMY_ADDRESS)

    withheld_tx_unsigned = bitcoind.createrawtransaction([{"txid":consolidate_txid, "vout": 0}], [{bitcoind_addr: round(float(bitcoind.getbalance())-0.01, 6)}])
    withheld_tx = bitcoind.signrawtransactionwithwallet(withheld_tx_unsigned)

    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    txid = bitcoind.sendtoaddress(addr, 10)

    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 4))
    poll_for_answer(EC_DAEMON_RPC_URL, request('broadcast', params={"tx":withheld_tx}))
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 5))

    bitcoind.generate(1)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 2))

@pytest.mark.parametrize("depth,first_status,second_status",[(1,4,5), (5,4,5), (6,2,2)])
@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getdspstatus_parent_depth(depth, first_status, second_status, fulcrum_service: Any) -> None:
    """ Verify the `getdspstatus` RPC does not handle deep chain of unconfirmed parents """
    bitcoind = get_bitcoind_rpc_connection()
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)

    bitcoind_addr = bitcoind.getnewaddress()
    consolidate_txid = bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    bitcoind.generatetoaddress(1, DUMMY_ADDRESS)

    withheld_tx_unsigned = bitcoind.createrawtransaction([{"txid":consolidate_txid, "vout": 0}], [{bitcoind_addr: round(float(bitcoind.getbalance())-0.01, 6)}])
    withheld_tx = bitcoind.signrawtransactionwithwallet(withheld_tx_unsigned)

    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    for i in range(0,depth):
        bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    txid = bitcoind.sendtoaddress(addr, 10)

    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', first_status))
    poll_for_answer(EC_DAEMON_RPC_URL, request('broadcast', params={"tx":withheld_tx}))
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', second_status))

    bitcoind.generate(1)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 2))

@pytest.mark.parametrize("num_inputs,first_status,second_status",[(1,4,5), (20,4,5), (21,2,2)])
@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getdspstatus_parent_width(num_inputs, first_status, second_status, fulcrum_service: Any) -> None:
    """ Verify the `getdspstatus` RPC does not handle deep chain of unconfirmed parents """
    bitcoind = get_bitcoind_rpc_connection()
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)

    bitcoind_addr = bitcoind.getnewaddress()
    consolidate_txid = bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    consolidate_txid = bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    bitcoind.generatetoaddress(1, DUMMY_ADDRESS)

    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    outputs = []
    output_value = round((float(bitcoind.getbalance())-0.01)/num_inputs, 6)
    for i in range(0,num_inputs):
        outputs.append({bitcoind.getnewaddress(): output_value})
    fan_out_tx_unsigned = bitcoind.createrawtransaction([{"txid":consolidate_txid, "vout": 0}], outputs)
    fan_out_tx = bitcoind.signrawtransactionwithwallet(fan_out_tx_unsigned)
    fan_out_txid = bitcoind.sendrawtransaction(fan_out_tx['hex'])
    bitcoind.generate(1)

    withheld_tx_unsigned = bitcoind.createrawtransaction([{"txid":fan_out_txid, "vout": 0}], [{bitcoind_addr: round((float(bitcoind.getbalance())-0.02)/num_inputs, 6)}])
    withheld_tx = bitcoind.signrawtransactionwithwallet(withheld_tx_unsigned)

    txid = bitcoind.sendtoaddress(addr, bitcoind.getbalance(), "", "", True)

    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', first_status))
    poll_for_answer(EC_DAEMON_RPC_URL, request('broadcast', params={"tx":withheld_tx}))
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', second_status))

    bitcoind.generate(1)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 2))


@pytest.mark.parametrize("sighash,first_status,second_status",[("ALL|FORKID",4,5),("NONE|FORKID",2,2),("SINGLE|FORKID",2,2),
                                                               ("ALL|FORKID|ANYONECANPAY",2,2),("NONE|FORKID|ANYONECANPAY",2,2),("SINGLE|FORKID|ANYONECANPAY",2,2),
                                                               ("ALL|FORKID|UTXOS",2,2),("NONE|FORKID|UTXOS",2,2),("SINGLE|FORKID|UTXOS",2,2)])
@pytest.mark.skipif(not SUPPORTED_PLATFORM, reason="Unsupported platform")
def test_getdspstatus_sighash(sighash, first_status, second_status, fulcrum_service: Any) -> None:
    """ Verify the `getdspstatus` RPC by checking status on an existing dsp """
    bitcoind = get_bitcoind_rpc_connection()
    bitcoind.generate(1)
    bitcoind.generatetoaddress(100, DUMMY_ADDRESS)

    bitcoind_addr = bitcoind.getnewaddress()
    consolidate_txid = bitcoind.sendtoaddress(bitcoind_addr, bitcoind.getbalance(), "", "", True)
    bitcoind.generatetoaddress(1, DUMMY_ADDRESS)

    withheld_tx_unsigned = bitcoind.createrawtransaction([{"txid":consolidate_txid, "vout": 0}], [{bitcoind_addr: round(float(bitcoind.getbalance())-0.01, 6)}])
    withheld_tx = bitcoind.signrawtransactionwithwallet(withheld_tx_unsigned)

    addr = poll_for_answer(EC_DAEMON_RPC_URL, request('getunusedaddress'))
    unsigned_tx = bitcoind.createrawtransaction([{"txid":consolidate_txid, "vout": 0}], [{addr: round(float(bitcoind.getbalance())-0.01, 6)}])
    signed_tx = bitcoind.signrawtransactionwithwallet(unsigned_tx, None, sighash)
    txid = bitcoind.sendrawtransaction(signed_tx['hex'])
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', first_status))
    poll_for_answer(EC_DAEMON_RPC_URL, request('broadcast', params={"tx":withheld_tx}))
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', second_status))

    bitcoind.generate(1)
    poll_for_answer(EC_DAEMON_RPC_URL, request('getdspstatus', params={"txid":txid}), expected_answer=('[*]', 2))