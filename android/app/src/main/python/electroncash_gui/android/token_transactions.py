from collections import namedtuple
from electroncash.simple_config import SimpleConfig
from electroncash.token import OutputData
from electroncash_gui.android.tokens import ConcreteTokenMeta, get_token_name

TokenHistory = namedtuple("TokenHistory",
                          ("tx_hash", "height", "conf", "timestamp", "amount", "balance",
                           "tokens_deltas", "tokens_balances", "token_name", "ft_amount_str",
                           "nft_amount_str", "ft_balance", "nft_balance", "category_id"))


def get_token_transactions(wallet):
    token_meta = ConcreteTokenMeta(SimpleConfig())
    all_history = wallet.get_history(include_tokens=True, include_tokens_balances=True)
    result = []
    for h in all_history:
        tx_hash, height, conf, timestamp, value, balance, tokens_deltas, tokens_balances = h
        if not tokens_deltas:
            continue

        for category_id, category_delta in h.tokens_deltas.items():
            ft_amount = category_delta.get("fungibles", 0)
            ft_amount_str = token_meta.format_amount(category_id, ft_amount, is_diff=True)
            cat_nfts_in = category_delta.get("nfts_in", [])
            cat_nfts_out = category_delta.get("nfts_out", [])
            ft_balance_ = tokens_balances.get(category_id, {}).get("fungibles", 0)
            ft_balance = token_meta.format_amount(category_id, ft_balance_)
            nft_balance = tokens_balances.get(category_id, {}).get("nfts", 0)
            nft_amount = len(cat_nfts_in) - len(cat_nfts_out)
            nft_amount_str = "{0:+d}".format(nft_amount) if nft_amount else "0"
            token_name = get_token_name(category_id) or category_id
            token_h = TokenHistory(
                tx_hash, height, conf, timestamp, value, balance, tokens_deltas, tokens_balances,
                token_name, ft_amount_str, nft_amount_str, str(ft_balance), str(nft_balance), category_id
            )
            result.append(token_h)
    return result


class NFT:
    def __init__(self, output_data: OutputData):
        self.id = output_data.id
        if output_data.is_minting_nft():
            self.capability = "minting"
        elif output_data.is_mutable_nft():
            self.capability = "mutable"
        else:
            self.capability = "immutable"
        self.commitment = output_data.commitment.hex()


def get_transaction_nfts(wallet, txid, category_id):

    all_history = wallet.get_history(include_tokens=True, include_tokens_balances=True)
    nfts_in = []
    nfts_out = []
    for h in all_history:
        tx_hash, _, _, _, _, _, tokens_deltas, _ = h
        if tokens_deltas and tx_hash == txid:
            for category_id_, category_delta in h.tokens_deltas.items():
                if category_id_ == category_id:
                    nfts_in_src = category_delta.get("nfts_in", [])
                    for nft in nfts_in_src:
                        nfts_in.append(NFT(nft[1]))
                    nfts_out_src = category_delta.get("nfts_out", [])
                    for nft in nfts_out_src:
                        nfts_out.append(NFT(nft[2]))
    return nfts_in, nfts_out
