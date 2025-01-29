#!/usr/bin/env python3

import subprocess
import shutil
import tempfile
import time
import os
import platform
from typing import Any, Generator
import pytest
import pytest_docker
import requests

from bitcoinrpc.authproxy import AuthServiceProxy
from jsonrpcclient import parse as rpc_parse, request, Error as rpc_Error, Ok as rpc_Ok
from jsonpath_ng import parse as path_parse

_datadir = None
_bitcoind = None

SUPPORTED_PLATFORM = platform.machine() in ("AMD64", "x86_64") and platform.system() in "Linux"

EC_DAEMON_RPC_URL = "http://user:pass@localhost:12342"
FULCRUM_STATS_URL = "http://{host}:{port}/stats"
BITCOIND_RPC_URL = "http://user:pass@{host}:{port}"

def poll_for_answer(url: Any, json_req: Any = None, expected_answer: Any = None, poll_interval: int = 1, poll_timeout: int = 10) -> Any:
    """ Poll an RPC method until timeout or an expected answer has been received """
    start = current = time.time()

    while current < start + poll_timeout:
        retry = False
        try:
            if json_req is None:
                resp = requests.get(url)
                json_result = resp.json()
            else:
                resp = requests.post(url, json=json_req)
                if resp.status_code == 500:
                    retry = True
                else:
                    parsed = rpc_parse(resp.json())
                    if isinstance(parsed, rpc_Ok):
                        json_result = parsed.result
                    else:
                        raise RuntimeError(f"Unable to parse JSON-RPC: {parsed.message}")

            if expected_answer is not None and not retry:
                path, answer = expected_answer
                jsonpath_expr = path_parse(path)
                expect_element = jsonpath_expr.find(json_result)
                if len(expect_element) > 0 and expect_element[0].value == answer:
                    return json_result
            elif retry:
                pass
            else:
                return json_result
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(poll_interval)
        current = time.time()
    raise TimeoutError("Timed out waiting for an answer")

def get_bitcoind_rpc_connection() -> AuthServiceProxy:
    if _bitcoind is not None:
        return _bitcoind
    raise RuntimeError("Bitcoind connection not created yet")

def make_bitcoind_rpc_connection(docker_ip: str, docker_services: pytest_docker.plugin.Services) -> AuthServiceProxy:
    """ Connects to bitcoind, generates 100 blocks and returns the connection """
    global _bitcoind
    global _datadir
    if _bitcoind is not None:
        return _bitcoind

    url = BITCOIND_RPC_URL.format(host=docker_ip, port=docker_services.port_for("bitcoind", 18443))

    _bitcoind = AuthServiceProxy(url)

    poll_for_answer(url, request('uptime'))
    block_count = _bitcoind.getblockcount()
    _bitcoind.unloadwallet("")
    wallet = _bitcoind.createwallet(_datadir +"/test_misc")
    if block_count < 101:
        _bitcoind.generate(101)
    _bitcoind.unloadwallet(wallet["name"])
    _bitcoind.createwallet(_datadir + "/test_other")
    return _bitcoind

# Creates a temp directory on disk for wallet storage
# Starts a deamon, creates and loads a wallet
def start_ec_daemon(docker_ip: str, docker_services: pytest_docker.plugin.Services) -> None:
    """
    Creates a temp directory on disk for wallet storage
    Starts a deamon, creates and loads a wallet
    """
    if _datadir is None:
        assert False
    os.mkdir(_datadir + "/regtest")
    shutil.copyfile("electroncash/tests/regtest/configs/electron-cash-config", _datadir + "/regtest/config")

    args = ["python3", "-m", "coverage", "run", "--data-file=.coverage-regtest"]

    fulcrum_ssl_port = docker_services.port_for("fulcrum", 51002)
    args += [
        "electron-cash",
        "-v",
        "--regtest",
        "-D",
        _datadir,
        "-w",
        _datadir + "/default_wallet",
        "daemon",
        "start",
        "--oneserver",
        "--server",
        f"{docker_ip}:{fulcrum_ssl_port}:s",
    ]

    subprocess.run(args, check=True)
    result = poll_for_answer(EC_DAEMON_RPC_URL, request("version"))

    from ...version import PACKAGE_VERSION
    assert result == PACKAGE_VERSION
    recreate_wallet()

def switch_wallet(name: str):
    if _datadir is None:
        return False
    bitcoind = get_bitcoind_rpc_connection()
    wallets = bitcoind.listwallets()
    for w in wallets:
        bitcoind.unloadwallet(w)
    bitcoind.loadwallet(_datadir + "/" + name)

def recreate_wallet():
    if _datadir is None:
        assert False
    wallet_file = _datadir+"/default_wallet"
    if os.path.isfile(wallet_file):
        r = request('close_wallet')
        result = poll_for_answer(EC_DAEMON_RPC_URL, r)
        if _datadir is None or _datadir.startswith("/tmp") is False:  # Paranoia
            assert False
        os.remove(_datadir+"/default_wallet")

    r = request('create', params={"wallet_path": wallet_file})
    assert r
    result = poll_for_answer(EC_DAEMON_RPC_URL, r)
    assert "seed" in result
    assert len(result["seed"].split(" ")) == 12

    result = poll_for_answer(EC_DAEMON_RPC_URL, request('load_wallet'))
    assert result

    # Wait until the wallet is up to date
    poll_for_answer(EC_DAEMON_RPC_URL, request('getinfo'), expected_answer=("wallets[\""+_datadir+"/default_wallet\"]", True))

def stop_ec_daemon() -> None:
    """ Stops the daemon and removes the wallet storage from disk """
    subprocess.run(["./electron-cash", "--regtest", "-D", _datadir, "daemon", "stop"], check=True)
    if _datadir is None or _datadir.startswith("/tmp") is False:  # Paranoia
        assert False
    shutil.rmtree(_datadir)

@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig) -> str:
    """ Needed since the docker-compose.yml is not in the root directory """
    return os.path.join(str(pytestconfig.rootdir), "electroncash/tests/regtest/docker-compose.yml")

@pytest.fixture(scope="session")
def fulcrum_service(docker_ip: str, docker_services: pytest_docker.plugin.Services) -> Generator[None, None, None]:
    """ Makes sure all services (bitcoind, fulcrum and the EC daemon) are up and running """
    global _datadir
    global _bitcoind
    if _datadir is not None:
        yield
    else:
        _datadir = tempfile.mkdtemp()
        _bitcoind = make_bitcoind_rpc_connection(docker_ip, docker_services)

        stats_url = FULCRUM_STATS_URL.format(host=docker_ip, port=docker_services.port_for("fulcrum", 8080))
        poll_for_answer(stats_url, expected_answer=('Controller.TxNum', 102))

        try:
            start_ec_daemon(docker_ip, docker_services)
            yield
        finally:
            stop_ec_daemon()
