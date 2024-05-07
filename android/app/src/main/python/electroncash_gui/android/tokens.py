from electroncash.token_meta import TokenMeta
from electroncash.simple_config import SimpleConfig
from electroncash.token import OutputData
from electroncash.wallet import TokenSendSpec
from typing import Any, Dict, Optional, Set


# Since the TokenMeta class from electroncash.token_meta.py is abstract, extend it here.

class ConcreteTokenMeta(TokenMeta):
    def _bytes_to_icon(self, buf: bytes) -> Any:
        return buf
    def _icon_to_bytes(self, icon: Any) -> bytes:
        return b''
    def gen_default_icon(self, token_id_hex: str) -> Any:
        return b''  # Placeholder

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
    if token_display_name is None:
        token_display_name = token_id  # Use token_id as name if no display name is found

    return token_display_name


def get_token_decimals(token_id: str) -> int:
    config = SimpleConfig()
    token_meta = ConcreteTokenMeta(config)
    decimals = token_meta.get_token_decimals(token_id)
    return decimals if decimals else 0


# This function is for fetching all the token categories and aggregating their fungible amounts and NFT amounts.
def get_tokens(wallet, category_id_filter=""):

    tok_utxos = wallet.get_utxos(tokens_only=True)
    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.
    token_meta = ConcreteTokenMeta(config)

    token_aggregate = {}
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
            token_bitfield = token_data.bitfield
            token_commitment = token_data.commitment.hex()
            output_data_instance = OutputData(bitfield=token_bitfield)
            is_nft = output_data_instance.has_nft()
            if output_data_instance.is_minting_nft():
                token_capability = "minting"
            elif output_data_instance.is_mutable_nft():
                token_capability = "mutable"
            else:
                token_capability = "immutable"

            if output_data_instance.has_nft():
                print(f"Token {token_id} is an NFT.")
            else:
                print(f"Token {token_id} is not an NFT.")

            # Fetch display name using token_meta, fall back to token_id if not found
            token_display_name = token_meta.get_token_display_name(token_id)
            if token_display_name is None:
                token_display_name = token_id  # Use token_id as name if no display name is found
            elif token_display_name.strip() == "":  # Remove whitespace.
                token_display_name = token_id

            if len(token_display_name) > 18:  # Shorten the display name to 18 chars.
                token_display_name = token_display_name[:12] + "..."

            # Aggregate fungible amounts and NFT count by token_id
            if token_id in token_aggregate:
                token_aggregate[token_id][0] += token_amount
            else:
                token_aggregate[token_id] = [token_amount, token_display_name, 0]
                nft_details[token_id] = []
                utxos[token_id] = []
            if is_nft:
                token_aggregate[token_id][2] += 1  # Increment NFT count if this utxo is an NFT
                nft_details[token_id].append([utxo_id, token_capability, token_commitment])
            utxos[token_id].append(utxo)

    # Convert the aggregated token data into the expected list of dictionaries format
    tokens = [{"tokenName": data[1], "amount": token_meta.format_amount(token_id, data[0]),
               "nft": data[2], "tokenId": token_id, "nftDetails": nft_details[token_id],
               "tokenUtxos": utxos[token_id]}
              for token_id, data in token_aggregate.items()]

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
    print(f"Fungible amount: {fungible_amount}")
    print(f"Fungible amount string: {fungibles_str}")
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
