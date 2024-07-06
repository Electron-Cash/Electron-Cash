#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2020 Jonald Fyookball
# With tweaks from Calin Culianu
# Part of the Electron Cash SPV Wallet
# License: MIT

'''
This implements the functionality for RPA (Reusable Payment Address) aka Paycodes
'''
import copy
import multiprocessing
import random
import threading
import time
import queue
import traceback
from decimal import Decimal as PyDecimal

from . import addr
from .. import bitcoin
from .. import networks
from .. import schnorr
from .. import transaction
from ..address import Address, Base58, ScriptOutput
from ..bitcoin import *  # COIN, TYPE_ADDRESS, sha256
from ..i18n import _
from ..plugins import run_hook
from ..transaction import Transaction, OPReturn
from ..keystore import KeyStore
from ..util import print_msg, print_error, do_in_main_thread


def _satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN * PyDecimal(amount)
               ) if amount not in ['!', None] else amount


def _resolver(wallet, x, nocheck):
    if x is None:
        return None
    if isinstance(x, (Address, ScriptOutput)):
        return x
    out = wallet.contacts.resolve(x)
    if out.get('type') == 'openalias' and not nocheck and not out.get('validated'):
        raise RuntimeError(f'cannot verify alias: {x}')
    return out['address']


def _mktx(wallet, config, outputs, fee=None, change_addr=None, domain=None, nocheck=False,
          locktime=None, op_return=None, op_return_raw=None, coins=None) -> Transaction:
    if op_return and op_return_raw:
        raise ValueError('Both op_return and op_return_raw cannot be specified together!')

    domain = None if domain is None else map(
        lambda x: _resolver(wallet, x, nocheck), domain)
    final_outputs = []
    if op_return:
        final_outputs.append(OPReturn.output_for_stringdata(op_return))
    elif op_return_raw:
        try:
            op_return_raw = op_return_raw.strip()
            tmp = bytes.fromhex(op_return_raw).hex()
            assert tmp == op_return_raw.lower()
            op_return_raw = tmp
        except Exception as e:
            raise ValueError("op_return_raw must be an even number of hex digits") from e
        final_outputs.append(OPReturn.output_for_rawhex(op_return_raw))

    for address, amount in outputs:
        address = _resolver(wallet, address, nocheck)
        amount = _satoshis(amount)
        final_outputs.append((TYPE_ADDRESS, address, amount))

    coins = coins or wallet.get_spendable_coins(domain, config)

    tx = None
    done = threading.Event()
    exc = None
    def make_tx_in_main_thread():
        """We need to do this in the main thread because otherwise wallet hooks that may run may get mad at us """
        nonlocal tx, exc
        try:
            try:
                tx = wallet.make_unsigned_transaction(coins, final_outputs, config, fee, change_addr)
            except Exception as e:
                print_error(f"Failed to create txn, caught exception: {e!r}")
                exc = e
                return
            if locktime is not None:
                tx.locktime = locktime
        finally:
            done.set()
    do_in_main_thread(make_tx_in_main_thread)
    done.wait()  # Wait for tx variable to get set
    if exc is not None:
        raise exc  # bubble exception out to caller
    assert isinstance(tx, Transaction)
    return tx


def _calculate_paycode_shared_secret(private_key, public_key, outpoint):
    """private key is expected to be an integer.
    public_key is expected to be bytes.
    outpoint is expected to be a string.
    returns the paycode shared secret as bytes"""

    from ..bitcoin import Point
    from ..bitcoin import curve_secp256k1 as curve

    # Public key is expected to be compressed.  Change into a point object.
    pubkey_point = bitcoin.ser_to_point(public_key)
    ecdsa_point = Point(curve, pubkey_point.x(), pubkey_point.y())

    # Multiply the public and private points together
    ecdh_product = ecdsa_point * private_key
    ecdh_x = int(ecdh_product.x())
    ecdh_x_bytes = ecdh_x.to_bytes(33, byteorder="big")

    # Get the hash of the product
    sha_ecdh_x_bytes = sha256(ecdh_x_bytes)
    sha_ecdh_x_as_int = int.from_bytes(sha_ecdh_x_bytes, byteorder="big")

    # Hash the outpoint string
    hash_of_outpoint = sha256(outpoint)
    hash_of_outpoint_as_int = int.from_bytes(hash_of_outpoint, byteorder="big")

    # Sum the ECDH hash and the outpoint Hash
    grand_sum = sha_ecdh_x_as_int + hash_of_outpoint_as_int

    # Hash the final result
    nbytes = (len("%x" % grand_sum) + 1) // 2
    grand_sum_bytes = grand_sum.to_bytes(nbytes, byteorder="big")
    shared_secret = sha256(grand_sum_bytes)

    return shared_secret


def _generate_address_from_pubkey_and_secret(parent_pubkey, secret):
    """parent_pubkey and secret are expected to be bytes
    This function generates a receiving address based on CKD."""

    new_pubkey = bitcoin.CKD_pub(parent_pubkey, secret, 0)[0]
    use_uncompressed = True

    # Currently, just uses compressed keys, but if this ever changes to
    # require uncompressed points:
    if use_uncompressed:
        pubkey_point = bitcoin.ser_to_point(new_pubkey)
        x_coord = hex(pubkey_point.x())[2:].zfill(64)
        y_coord = hex(pubkey_point.y())[2:].zfill(64)
        uncompressed = "04" + \
            hex(pubkey_point.x())[2:].zfill(64) + \
            hex(pubkey_point.y())[2:].zfill(64)
        new_pubkey = bytes.fromhex(uncompressed)
    return Address.from_pubkey(new_pubkey)


def _generate_privkey_from_secret(parent_privkey, secret):
    """parent_privkey and secret are expected to be bytes
    This function generates a receiving address based on CKD."""
    return bitcoin.CKD_priv(parent_privkey, secret, 0)[0].hex()


def get_grind_string(wallet, prefix_size="10"):

    if prefix_size == "04":
        prefix_chars = 1
    elif prefix_size == "08":
        prefix_chars = 2
    elif prefix_size == "0C":
        prefix_chars = 3
    elif prefix_size == "10":
        prefix_chars = 4
    else:
        raise ValueError("Invalid prefix size. Must be 4,8,12, or 16 bits.")

    scanpubkey = wallet.derive_pubkeys(0, 0)
    grind_string = scanpubkey[2:prefix_chars + 2].upper()
    return grind_string


def generate_paycode(wallet, prefix_size="10"):
    """prefix size should be either 0x04 , 0x08, 0x0C, 0x10"""

    # Fields of the paycode
    version = "01"
    if networks.net.TESTNET:
        version = "05"
    scanpubkey = wallet.derive_pubkeys(0, 0)
    spendpubkey = wallet.derive_pubkeys(0, 1)
    expiry = "00000000"

    # Concatenate
    payloadstring = version + prefix_size + scanpubkey + spendpubkey + expiry

    # Convert to bytes
    payloadbytes = bytes.fromhex(payloadstring)

    # Generate paycode "address" via rpa.addr function
    prefix = networks.net.RPA_PREFIX
    return addr.encode_full(prefix, addr.PUBKEY_TYPE, payloadbytes)


def _swap_dummy_for_destination(tx: Transaction, rpa_dummy_address: Address, rpa_destination_address: Address):
    for i, (typ, addr, val) in enumerate(tx._outputs.copy()):
        # Compare the address to see if it's the one we need to swap
        if addr == rpa_dummy_address:
            # Do the swap
            tx._outputs[i] = (typ, rpa_destination_address, val)
    # It is necessary to re-initialize "raw" so the output swap becomes part of transaction when it is later serialized
    tx.raw = None


def generate_transaction_from_paycode(wallet, config, amount, rpa_paycode, fee=None, from_addr=None,
                                      change_addr=None, nocheck=False, password=None, locktime=None,
                                      op_return=None, op_return_raw=None, progress_callback=None, exit_event=None,
                                      coins=None):
    if not wallet.is_schnorr_enabled():
        raise RuntimeError(_("You must enable Schnorr signing in settings for this wallet in order to send to a paycode"
                             " address."))
    if not schnorr.has_fast_sign() or not schnorr.has_fast_verify():
        raise RuntimeError(_("Schnorr \"fast signing\" is unavailable, cannot proceed.\n\n"
                             "In order to enable Schnorr fast-signing, please ensure you have built and installed the"
                             " BCH-specific libsecp256k1 library."))

    exit_event = exit_event or threading.Event()  # Since we rely on exit_event below, ensure it's valid regardless
    # Decode the paycode
    rprefix, addr_hash = addr.decode(rpa_paycode)
    paycode_hex = addr_hash.hex().upper()

    # Parse paycode
    paycode_field_version = paycode_hex[0:2]
    paycode_field_prefix_size = paycode_hex[2:4]
    paycode_field_scan_pubkey = paycode_hex[4:70]
    paycode_field_spend_pubkey = paycode_hex[70:136]
    paycode_field_expiry = paycode_hex[136:144]
    paycode_field_checksum = paycode_hex[144: 154]

    paycode_expiry = int.from_bytes(bytes.fromhex(paycode_field_expiry), byteorder='big', signed=False)
    if paycode_expiry != 0:
        one_week_from_now = int(time.time()) + 604800
        if paycode_expiry < one_week_from_now:
            raise RuntimeError('Paycode expired.')

    # Initialize a few variables for the transaction
    tx_fee = _satoshis(fee)
    domain = from_addr.split(',') if from_addr else None

    if paycode_field_prefix_size == "04":
        prefix_chars = 1
    elif paycode_field_prefix_size == "08":
        prefix_chars = 2
    elif paycode_field_prefix_size == "0C":
        prefix_chars = 3
    elif paycode_field_prefix_size == "10":
        prefix_chars = 4
    else:
        raise ValueError("Invalid prefix size. Must be 4,8,12, or 16 bits.")

    # Construct the transaction, initially with a dummy destination
    rpa_dummy_privkey = sha256(b"rpadummy" + random.getrandbits(32).to_bytes(4, 'big'))
    rpa_dummy_pubkey = bitcoin.public_key_from_private_key(rpa_dummy_privkey, True)
    rpa_dummy_address = Address.from_pubkey(rpa_dummy_pubkey)

    tx = _mktx(wallet, config, [(rpa_dummy_address, amount)], tx_fee, change_addr, domain, nocheck,
               locktime, op_return, op_return_raw, coins=coins)

    # Use the first input (input zero) for our shared secret
    input_zero = tx._inputs[0]

    # Fetch our own private key for the coin
    bitcoin_addr = input_zero["address"]
    private_key_wif_format = wallet.export_private_key(bitcoin_addr, password)
    private_key_int_format = int.from_bytes(Base58.decode_check(private_key_wif_format)[1:33], byteorder="big")

    # Grab the outpoint (the colon is intentionally omitted from the string)
    outpoint_string = str(input_zero["prevout_hash"]) + str(input_zero["prevout_n"])

    # Format the pubkey in preparation to get the shared secret
    scanpubkey_bytes = bytes.fromhex(paycode_field_scan_pubkey)

    # Calculate shared secret
    shared_secret = _calculate_paycode_shared_secret(private_key_int_format, scanpubkey_bytes, outpoint_string)

    # Get the real destination for the transaction
    rpa_destination_address = _generate_address_from_pubkey_and_secret(bytes.fromhex(paycode_field_spend_pubkey), shared_secret)

    # Swap the dummy destination for the real destination
    _swap_dummy_for_destination(tx, rpa_dummy_address, rpa_destination_address)

    # Sort just outputs deterministically; must be done before we sign. We do this again even though
    # make_unsigned_transaction() already sorted the txn for us. Must do this again because we changed
    # one of the outputs in the line above, and it may end up sorting differently. This is a privacy measure.
    tx.BIP69_sort(sort_inputs=False, sort_outputs=True)

    # Belt-and-suspenders check that the tx definitely has the rpa_dummy_address removed,
    # and that it has the rpa_destination_address added
    if any(addr == rpa_dummy_address for _, addr, _ in tx.outputs()):
        raise RuntimeError('Internal check failed: Transaction is still sending to the rpa_dummy_address. FIXME!')
    if not any(addr == rpa_destination_address for _, addr, _ in tx.outputs()):
        raise RuntimeError('Internal check failed: Transaction is somehow *not* sending to the rpa_destination_address.'
                           ' FIXME!')

    # Now we need to sign the transaction after the outputs are known
    wallet.sign_transaction(tx, password)

    # Setup wallet and keystore in preparation for signature grinding
    my_keystore = wallet.get_keystore()

    # We assume one signature per input, for now...
    assert len(input_zero["signatures"]) == 1
    input_zero["signatures"] = [None]  # Clear sig since we must re-sign during grind below

    # Keypair logic from transaction module
    keypairs = my_keystore.get_tx_derivations(tx)
    for k, v in keypairs.items():
        keypairs[k] = my_keystore.get_private_key(v, password)
    txin = input_zero
    pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
    for j, (pubkey, x_pubkey) in enumerate(zip(pubkeys, x_pubkeys)):
        if pubkey in keypairs:
            _pubkey = pubkey
        elif x_pubkey in keypairs:
            _pubkey = x_pubkey
        else:
            continue
        sec, compressed = keypairs.get(_pubkey)

    # Get the keys and preimage ready for signing
    pubkey = bytes.fromhex(public_key_from_private_key(sec, compressed))
    nHashType = 0x00000041  # hardcoded, perhaps should be taken from unsigned input dict
    pre_hash = Hash(bfh(tx.serialize_preimage(0, nHashType, use_cache=False)))

    # While loop for grinding.  Keep grinding until txid prefix matches
    # paycode scanpubkey prefix.
    grind_count = 0
    progress_count = 0

    if progress_callback:
        do_in_main_thread(progress_callback, progress_count)

    # The below unrolls some of the Transacton class signing code into here, to optimize it. It's much faster this
    # way, even if a bit complex. -Calin
    def my_sign(sec: bytes, pre_hash: bytes, ndata: bytes, nHashType: int):
        sig = schnorr.sign(sec, pre_hash, ndata=ndata)
        return sig + bytes((nHashType & 0xff,))

    search_space = 0xff_ff_ff_ff_ff
    ser_prefix = Transaction.serialize_outpoint_bytes(txin)
    script_prefix = push_script_bytes(bytes((0x0,) * 65))[:-65]  # create the push prefix e.g. 0x41
    script_suffix = push_script_bytes(pubkey)  # push of the pubkey
    script_prefix = var_int_bytes(len(script_prefix) + 65 + len(script_suffix)) + script_prefix  # prepend length byte
    ser_suffix = int_to_bytes(txin.get('sequence', 0xffffffff - 1), 4)
    prefix_target_hex = paycode_field_scan_pubkey[2:prefix_chars + 2].lower()
    n_threads = multiprocessing.cpu_count()
    tx_matches_paycode_prefix = False
    t0 = time.time()
    results = queue.Queue()

    def thread_func(thread_num):
        try:
            nonlocal grind_count, tx_matches_paycode_prefix, progress_count
            nonce = (search_space // n_threads) * thread_num
            my_tx = copy.deepcopy(tx)
            my_txin = my_tx._inputs[0]
            while not tx_matches_paycode_prefix:
                if exit_event.is_set():
                    results.put(None)  # NoneType indicates user cancelled
                    return
                nonce_bytes = nonce.to_bytes(length=5, byteorder='little')
                ndata = sha256(nonce_bytes)
                signature = my_sign(sec, pre_hash, ndata, nHashType)
                assert len(signature) == 65
                serialized_input = ser_prefix + script_prefix + signature + script_suffix + ser_suffix

                if progress_callback and progress_count < grind_count // 1000:
                    progress_count = grind_count // 1000
                    do_in_main_thread(progress_callback, progress_count)

                hashed_input = sha256(sha256(serialized_input))
                hashed_input_prefix_hex = hashed_input[:2].hex()[0:prefix_chars]

                if hashed_input_prefix_hex == prefix_target_hex:
                    print_error(f"matched prefix {prefix_target_hex} for serialized input with hash: {hashed_input.hex()}")
                    reason=[]
                    if not Transaction.verify_signature(pubkey, signature[:-1], pre_hash, reason=reason):
                        raise RuntimeError(f"Signature verification failed: {str(reason)}")
                    else:
                        my_txin['signatures'][0] = signature.hex()
                        my_txin['pubkeys'][0] = pubkey.hex()
                        check_input = my_tx.serialize_input_bytes(my_txin, bytes.fromhex(my_tx.input_script(my_txin)))
                        check_hash = Hash(check_input)
                        if hashed_input != check_hash:
                            print_error(f"Real input hash: {check_hash.hex()} does not match what we calculated: {hashed_input.hex()}")
                            print_error(f"our ser input : {serialized_input.hex()}")
                            print_error(f"real ser input: {check_input.hex()}")
                            raise RuntimeError("Internal error calculating the input prefix. Calculated prefix does not"
                                               " match what the Transaction class would have done. FIXME!")
                        tx_matches_paycode_prefix = True
                        results.put(my_tx)
                grind_count += 1
                nonce += 1
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            results.put(e)

    threads = []
    for i in range(n_threads):
        threads.append(threading.Thread(target=thread_func, args=(i,), name=f"RPA grinder thread {i + 1}"))
        threads[-1].start()
    tx_or_e = results.get(block=True)

    def join_threads():
        exit_event.set()  # Just in case, get sub-threads to stop
        for t in threads:
            t.join()

    try:
        if isinstance(tx_or_e, Exception):
            # This should never happen. Sub-thread got an exception. Bubble it out.
            raise tx_or_e
        elif tx_or_e is None:
            # User cancelled
            return
        tx = tx_or_e
    finally:
        join_threads()
    tf = time.time()
    print_error(f"RPA grind: Using {n_threads} threads, iterated {grind_count} times in {tf-t0:1.3f} secs")

    # Re-serialize the transaction.
    retval = tx.raw = tx.serialize()

    # Return a raw transaction string
    return retval


def extract_private_keys_from_transaction(wallet, raw_tx, password=None):
    # Initialize return value.  Will return empty list if no private key can be found.
    retval = []

    # Deserialize the raw transaction
    unpacked_tx = Transaction(raw_tx).deserialize()

    # Get a list of output addresses (we will need this for later to check if
    # our key matches)
    output_addresses = []
    outputs = unpacked_tx["outputs"]
    for i in outputs:
        if isinstance(i['address'], Address):
            output_addresses.append(
                i['address'].to_string(
                    Address.FMT_CASHADDR))

    # Variables for looping
    inputs = unpacked_tx["inputs"]
    number_of_inputs = len(inputs)
    max_inputs_as_per_rpa_spec = 30

    # Process each input until we find one that creates the shared secret to
    # get a private key for an output
    for input_index in range(0, min(max_inputs_as_per_rpa_spec, number_of_inputs)):
        # Grab the outpoint
        single_input = inputs[input_index]
        prevout_hash = single_input["prevout_hash"]
        prevout_n = str(single_input["prevout_n"])  # n is int. convert to str.
        outpoint_string = prevout_hash + prevout_n  # Intentionally omits the ':' char

        # Get the pubkey of the sender from the scriptSig.
        scriptSig = bytes.fromhex(single_input["scriptSig"])
        d = {}
        transaction.parse_scriptSig(d, scriptSig)  # Populates `d`

        sender_pubkey = None
        if "pubkeys" in d:
            sender_pubkey_string = d["pubkeys"][0]
            if isinstance(sender_pubkey_string, str):
                if all(c in "0123456789ABCDEFabcdef" for c in sender_pubkey_string):
                    sender_pubkey = bytes.fromhex(d["pubkeys"][0])

        if sender_pubkey is None:
            # This scriptsig either doesn't have a key (coinbase tx, etc), or the xpubkey in the scriptsig is not a
            # hex string (P2PK, etc), or is not a scriptSig we can understand
            continue

        sender_pubkey = bytes.fromhex(d["pubkeys"][0])

        # We need the private key that corresponds to the scanpubkey.
        # In this implementation, this is the one that goes with receiving
        # address 0
        scanpubkey = wallet.derive_pubkeys(0, 0)

        scan_private_key_wif_format = wallet.export_private_key_from_index(
            (False, 0), password)

        scan_private_key_int_format = int.from_bytes(Base58.decode_check(scan_private_key_wif_format)[1:33],
                                                     byteorder="big")
        # Calculate shared secret
        shared_secret = _calculate_paycode_shared_secret(
            scan_private_key_int_format, sender_pubkey, outpoint_string)

        # Get the spendpubkey for our paycode.
        # In this implementation, simply: receiving address 1.
        spendpubkey = wallet.derive_pubkeys(0, 1)

        # Get the destination address for the transaction
        destination = _generate_address_from_pubkey_and_secret(bytes.fromhex(spendpubkey), shared_secret).to_string(
            Address.FMT_CASHADDR)

        # Fetch our own private (spend) key out of the wallet.
        spendpubkey = wallet.derive_pubkeys(0, 1)
        spend_private_key_wif_format = wallet.export_private_key_from_index(
            (False, 1), password)
        spend_private_key_int_format = int.from_bytes(Base58.decode_check(spend_private_key_wif_format)[1:33],
                                                      byteorder="big")

        # Generate the private key for the money being received via paycode
        spend_private_key_hex_format = hex(spend_private_key_int_format)[2:]

        # Pad with leading zero if necesssary
        if len(spend_private_key_hex_format) % 2 !=0:
            spend_private_key_hex_format = "0" + spend_private_key_hex_format

        privkey = _generate_privkey_from_secret(bytes.fromhex(
            spend_private_key_hex_format), shared_secret)

        # Now convert to WIF
        extendedkey = bytes((networks.net.WIF_PREFIX,)).hex() + privkey
        extendedkey_bytes = bytes.fromhex(extendedkey)
        checksum = bitcoin.Hash(extendedkey).hex()[0:8]
        key_with_checksum = extendedkey + checksum
        privkey_wif = bitcoin.EncodeBase58Check(extendedkey_bytes)

        # Check the address matches
        if destination in output_addresses:
            retval.append(privkey_wif)

    return retval


def determine_best_rpa_start_height(wallet_creation_timestamp=1704000000, *, net=None):
    name = 'determine_best_rpa_start_height'
    net = net or networks.net
    if not net:
        raise RuntimeError('Cannot call determine_best_rpa_start_height without an app-level `net` already set.')
    default_height = net.RPA_START_HEIGHT
    if net.asert_daa.anchor is None:
        print_error(f"{name}: WARNING - Current network {str(type(net))} lacks an ASERT anchor."
                    f" Will just return the default height for this network ({default_height})")
        return default_height
    # formula to determine a rough block height for this timestamp
    anchor_height = net.asert_daa.anchor.height
    anchor_ts = net.asert_daa.anchor.prev_time
    # The height is minimum net.RPA_START_HEIGHT, but may be after it if the user specified a timestamp
    height = max(default_height, anchor_height + round((wallet_creation_timestamp - anchor_ts) / 600))
    # print_error(f"{name}: Calculated height {height} for this network from timestamp {wallet_creation_timestamp}")
    return height
