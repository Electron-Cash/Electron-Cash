from typing import Any, Dict, Optional, Set

from electroncash import address, bitcoin
from electroncash.simple_config import SimpleConfig
from electroncash.token import OutputData, Structure, Capability
from electroncash.token_meta import TokenMeta
from electroncash.wallet import TokenSendSpec

TYPE_ADDRESS = 0


# Since the TokenMeta class from electroncash.token_meta.py is abstract, extend it here.

class ConcreteTokenMeta(TokenMeta):
    def _bytes_to_icon(self, buf: bytes) -> Any:
        return buf
    def _icon_to_bytes(self, icon: Any) -> bytes:
        return b''
    def gen_default_icon(self, token_id_hex: str) -> Any:
        return b''  # Placeholder


def create_and_sign_genesis_transaction(wallet,   fungible_amount, is_nft, nft_capability, password):

    try:
        eligible_utxos = fetch_eligible_genesis_utxos(wallet)
        utxo_dict = eligible_utxos[0]
    except Exception as e:
        print ("couldn't get an eligible utxo")
        return

    # Define the bitfield based on input parameters
    bitfield = 0
    if fungible_amount > 0:
        bitfield |= Structure.HasAmount.value
    if is_nft:
        bitfield |= Structure.HasNFT.value
        if nft_capability == "Mutable":
            bitfield |= Capability.Mutable.value
        elif nft_capability == "Minting":
            bitfield |= Capability.Minting.value

    # Create the token output data
    try:
        prevout_hash = utxo_dict['prevout_hash']
        token_id_bytes = bytes.fromhex(prevout_hash)[::-1]
    except Exception as e:
        print("Failed to process 'prevout_hash': ", str(e))
        return
    token_id_bytes = bytes.fromhex(utxo_dict['prevout_hash'])[::-1]


    # Create the token output data
    try:
        tok = OutputData(id=token_id_bytes, amount=fungible_amount, bitfield=bitfield)
    except Exception as e:
        print("Failed to create OutputData: ", str(e))

    dust_limit_for_token_bearing_output=800
    change_addr = wallet.get_unused_address(for_change=True, frozen_ok=False) or utxo["address"]
    token_addr = wallet.get_unused_address(for_change=False, frozen_ok=False) or utxo["address"]

    outputs = [(TYPE_ADDRESS, change_addr, '!'),(TYPE_ADDRESS, token_addr,  dust_limit_for_token_bearing_output)]
    token_datas = [None, tok]
    config = SimpleConfig()  # Ok to have a locally scoped config
    tx = wallet.make_unsigned_transaction(inputs=[utxo_dict], outputs=outputs, config=config,token_datas=token_datas, bip69_sort=False)

    # Sign the TX
    wallet.sign_transaction(tx,password)
    # Return to the frontend for broadcasting through the android daemon
    return tx


def create_and_sign_new_coin_tx(wallet,password):

    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.

    # Create new coin in case we have no coins eligible for token genesis (e.g. no prevout = 0 coins)
    # Fetch UTXOs suitable for creating a new coin
    utxos = wallet.get_utxos(exclude_frozen=True, mature=True, confirmed_only=False, exclude_slp=True, exclude_tokens=True)

    # Sort UTXOs by descending 'prevout_n' and descending 'value' to prefer UTXOs with non-zero output numbers first
    sorted_utxos = sorted(utxos, key=lambda x: (-x['prevout_n'], -x['value']))

    if not sorted_utxos:
        # No coins available
        return None

    # Select the UTXO with the highest value and appropriate 'prevout_n'
    selected_utxo = sorted_utxos[0]

    # Attempt to get an unused address for the transaction; if unavailable, use the UTXO's address
    address = wallet.get_unused_address(for_change=True, frozen_ok=False) or selected_utxo['address']

    try:
        # Create an unsigned transaction
        tx = wallet.make_unsigned_transaction(
            inputs=[selected_utxo],  # Use the selected UTXO as input
            outputs=[(bitcoin.TYPE_ADDRESS, address, '!')],  # Send output to the new address
            config=config
        )

    except Exception as e:
        print(f"Error creating transaction: {e}")
        return None

    # Sign the TX
    wallet.sign_transaction(tx,password)
    # Return to the frontend for broadcasting through the android daemon
    return tx


def wallet_has_genesis_utxo(wallet):
    # Get the eligible utxos from the wallet layer.
    eligible_utxos = fetch_eligible_genesis_utxos(wallet)
    # Return Boolean Value showing whether or not the wallet has a genesis UTXO.
    if len(eligible_utxos) == 0:
        return False
    else:
        return True


def fetch_eligible_genesis_utxos(wallet):

    # Use the wallet's method to get UTXOs excluding those not suitable for genesis tokens
    utxos = wallet.get_utxos(exclude_frozen=True, mature=True, confirmed_only=False, exclude_slp=True, exclude_tokens=True)

    # Calculate the minimum value required for a UTXO to be eligible for creating a new token
    min_val = 1310 # Hardcoded for now, based on 800s heuristic dust limit and 310 byte txn.

    eligible_utxos = []
    for utxo in utxos:
        # Check if the UTXO can create a new token, typically prevout_n should be 0 for token creation
        if utxo['prevout_n'] == 0 and utxo['value'] >= min_val:
            eligible_utxos.append(utxo)
    return eligible_utxos


# This function is for saving the display name to the metadata.
def save_token_data(token_id, display_name, decimals):

    # Initialize TokenMeta class
    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.
    token_meta = ConcreteTokenMeta(config)

    # Set the display name:
    token_id_hex = token_id
    new_display_name = display_name
    token_meta.set_token_display_name(token_id_hex, new_display_name)
    token_meta.set_token_decimals(token_id_hex, decimals)
    token_meta.save()  # Save to storage


# This function is for fetching a single token display name.  Called when we edit the name on the UI.
def get_token_name(token_id: str) -> str:
    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.
    token_meta = ConcreteTokenMeta(config)

    # Fetch display name using token_meta
    token_display_name = token_meta.get_token_display_name(token_id)

    # If nothing was set in the metadata, return empty string to the UI
    if token_display_name is None:
        return ""

    # Otherwise return the value
    return token_display_name


def get_token_decimals(token_id: str) -> int:
    config = SimpleConfig()
    token_meta = ConcreteTokenMeta(config)
    decimals = token_meta.get_token_decimals(token_id)
    return decimals if decimals else 0


def get_tokens(wallet, category_id_filter=""):
    tok_utxos = wallet.get_utxos(tokens_only=True)
    config = SimpleConfig()  # Locally scoped config for token metadata instantiation
    token_meta = ConcreteTokenMeta(config)

    named_tokens = {}
    unnamed_tokens = {}
    nft_details = {}
    utxos = {}
    for utxo in tok_utxos:
        token_data = utxo.get('token_data')
        utxo_id = f"{utxo.get('prevout_hash')}:{utxo.get('prevout_n')}"
        if token_data:
            token_id = token_data.id[::-1].hex()  # Reverse byte order and convert to hex
            if category_id_filter and token_id != category_id_filter:
                continue
            token_amount = token_data.amount
            token_commitment = token_data.commitment.hex()
            output_data = OutputData(bitfield=token_data.bitfield)
            is_nft = output_data.has_nft()
            if output_data.is_minting_nft():
                token_capability = "minting"
            elif output_data.is_mutable_nft():
                token_capability = "mutable"
            else:
                token_capability = "immutable"

            # Fetch display name using token_meta, fall back to token_id if not found or empty
            token_display_name = token_meta.get_token_display_name(token_id)
            if token_display_name is None or token_display_name.strip() == "":
                token_display_name = token_id

            # Truncate the display name to a max of 18 characters
            if len(token_display_name) > 18:
                token_display_name = token_display_name[:15] + "..."

            # Choose the correct dictionary based on whether the token has a name
            target_dict = named_tokens if token_display_name != token_id else unnamed_tokens

            # Aggregate fungible amounts, NFT count, NFT details and UTXOs by token_id
            if token_id in target_dict:
                target_dict[token_id][0] += token_amount
            else:
                target_dict[token_id] = [token_amount, token_display_name, 0]
                nft_details[token_id] = []
                utxos[token_id] = []

            # Increment NFT count if applicable
            if is_nft:
                target_dict[token_id][2] += 1
                nft_details[token_id].append([utxo_id, token_capability, token_commitment])
            utxos[token_id].append(utxo)

    # Sort each dictionary separately
    sorted_named = sorted(named_tokens.items(), key=lambda x: x[1][1])  # Sort by name
    sorted_unnamed = sorted(unnamed_tokens.items(), key=lambda x: int(x[0], 16))  # Sort by numerical value of token_id

    # Concatenate sorted lists
    sorted_tokens = sorted_named + sorted_unnamed

    # Convert to expected list of dictionaries format
    tokens = [{"tokenName": data[1], "amount": token_meta.format_amount(token_id, data[0]),
               "nft": data[2], "tokenId": token_id, "nftDetails": nft_details[token_id],
               "tokenUtxos": utxos[token_id]}
              for token_id, data in sorted_tokens]

    return tokens


def get_outpoint_longname(utxo) -> str:
    return f"{utxo['prevout_hash']}:{utxo['prevout_n']}"


def make_tx(wallet, config, to_address, fee_rate, category_id, fungibles_str, nft) -> TokenSendSpec:
    token_meta = ConcreteTokenMeta(SimpleConfig())
    spec = TokenSendSpec()
    spec.payto_addr = to_address
    spec.change_addr = (wallet.get_unused_address(for_change=True, frozen_ok=False)
                        or wallet.dummy_address())
    spec.feerate = fee_rate  # sats/KB
    spec.send_satoshis = 0
    utxos = get_tokens(wallet, category_id)[0]["tokenUtxos"]
    spec.token_utxos = {get_outpoint_longname(utxo): utxo for utxo in utxos}

    spec.non_token_utxos = {get_outpoint_longname(x): x
                            for x in wallet.get_spendable_coins(None, config)}
    fungible_amount = token_meta.parse_amount(category_id, fungibles_str)
    spec.send_fungible_amounts = {category_id: fungible_amount}
    spec.send_nfts = set()
    if nft:
        spec.send_nfts.add(nft)
    return wallet.make_token_send_tx(config, spec)


def format_fungible_amount(category_id, amount) -> str:
    token_meta = ConcreteTokenMeta(SimpleConfig())
    return token_meta.format_amount(category_id, amount)


def parse_fungible_amount(category_id, amount_str) -> int:
    token_meta = ConcreteTokenMeta(SimpleConfig())
    return token_meta.parse_amount(category_id, amount_str)
