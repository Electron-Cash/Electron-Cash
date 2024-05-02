from functools import partial


def get_addresses(wallet, type, status):
    result = []
    if type != 2:  # Not change
        result += filter_addresses(wallet, wallet.get_receiving_addresses(), status)
    if type != 1:  # Not receiving
        result += filter_addresses(wallet, wallet.get_change_addresses(), status)
    return result


def filter_addresses(wallet, addresses, status):
    return filter(partial(FILTERS[status], wallet), addresses)


FILTERS = {
    0:  # All
        lambda wallet, addr: True,
    1:  # Used
        lambda wallet, addr: (wallet.get_address_history(addr) and
                              not wallet.get_addr_balance(addr)[0]),
    2:  # Funded
        lambda wallet, addr: wallet.get_addr_balance(addr)[0],
    3:  # Unused
        lambda wallet, addr: not wallet.get_address_history(addr),
}
