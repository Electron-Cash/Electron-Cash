from electroncash.token_meta import TokenMeta
from electroncash.simple_config import SimpleConfig
from electroncash.token import OutputData
from typing import Any, Dict, Optional
 

# Since the TokenMeta class from electroncash.token_meta.py is abstract, extend it here.

class ConcreteTokenMeta(TokenMeta):
    def _bytes_to_icon(self, buf: bytes) -> Any: 
        return buf  
    def _icon_to_bytes(self, icon: Any) -> bytes: 
        return b''  
    def gen_default_icon(self, token_id_hex: str) -> Any: 
        return b''  # Placeholder
 
# This function is for saving the display name to the metadata.
def save_token_data(token_id, display_name): 

    # Initialize TokenMeta class
    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.
    token_meta = ConcreteTokenMeta(config)

    # Set the display name:
    token_id_hex = token_id
    new_display_name = display_name
    token_meta.set_token_display_name(token_id_hex, new_display_name) 
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
    
# This function is for fetching all the token categories and aggregating their fungible amounts and NFT amounts. 
def get_tokens(wallet): 
    
    tok_utxos = wallet.get_utxos(tokens_only=True) 
    config = SimpleConfig()  # Ok to have a locally scoped new instead of config for purposes of instatiating the token meta.
    token_meta = ConcreteTokenMeta(config)

    token_aggregate = {}
    for utxo in tok_utxos:   
        token_data = utxo.get('token_data')   
        if token_data:
            token_id = token_data.id[::-1].hex()  # Reverse byte order and convert to hex
            token_amount = token_data.amount 
            token_bitfield = token_data.bitfield
            output_data_instance = OutputData(bitfield=token_bitfield)
            is_nft = output_data_instance.has_nft()
            
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
                token_aggregate[token_id] = [token_amount, token_display_name,0]
            if is_nft:
                token_aggregate[token_id][2] += 1  # Increment NFT count if this utxo represents an NFT

    # Convert the aggregated token data into the expected list of dictionaries format
    tokens = [{"tokenName": data[1], "amount": str(data[0]), "nft": data[2], "tokenId": token_id} 
              for token_id, data in token_aggregate.items()]
 
    return tokens

