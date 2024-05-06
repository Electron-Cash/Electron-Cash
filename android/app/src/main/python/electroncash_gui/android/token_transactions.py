from collections import namedtuple
from electroncash.simple_config import SimpleConfig
from electroncash_gui.android.tokens import ConcreteTokenMeta, get_token_name

TokenHistory = namedtuple("TokenHistory",
                          ("tx_hash", "height", "conf", "timestamp", "amount", "balance",
                           "tokens_deltas", "tokens_balances", "token_name", "ft_amount_str",
                           "nft_amount_str", "ft_balance", "nft_balance"))


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
            ft_amount_str = token_meta.format_amount(category_id, ft_amount)
            cat_nfts_in = category_delta.get("nfts_in", [])
            cat_nfts_out = category_delta.get("nfts_out", [])
            ft_balance_ = tokens_balances.get(category_id, {}).get("fungibles", 0)
            ft_balance = token_meta.format_amount(category_id, ft_balance_)
            nft_balance_ = tokens_balances.get(category_id, {}).get("nfts", 0)
            nft_balance = token_meta.format_amount(category_id, nft_balance_)
            nft_amount = len(cat_nfts_in) - len(cat_nfts_out)
            nft_amount_str = "{0:+d}".format(nft_amount) if nft_amount else "0"
            token_name = get_token_name(category_id)
            token_h = TokenHistory(
                tx_hash, height, conf, timestamp, value, balance, tokens_deltas, tokens_balances,
                token_name, ft_amount_str, nft_amount_str, str(ft_balance), str(nft_balance))
            result.append(token_h)
    return result
