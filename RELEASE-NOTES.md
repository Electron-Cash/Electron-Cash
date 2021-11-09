Electrum ABC is a fork of the open source Electron Cash wallet for eCash.

The Electrum ABC software is NOT affiliated, associated, or endorsed by
Electron Cash, electroncash.org, Electrum or electrum.org.


# Usage

When you first run Electrum ABC it will use a different configuration
directory to Electron Cash. On Unix it is ".electrum-abc", and on Windows/MacOS
it is "ElectrumABC".  Your wallet files will be copied from the Electron Cash
configuration directory if found.

Initially transactions will show up as unverified because
Electrum ABC is downloading the blockchain headers to verify the transactions.
This can take up to 10 minutes, but is only done once.

Ensure you are running Electrum ABC and not Electron Cash by checking for
"Electrum ABC" in the title bar wording.

We STRONGLY recommend you get comfortable and only send a small amount of eCash
coins at first, to yourself, to confirm the network is processing your
transactions as expected.


# Release notes

## Release 5.0.3

- Add a coin consolidation tool to reduce the number of UTXOs for a single address (#142).
- Improve the support for Satochip hardware wallets (#143):
  - use BIP39 seeds by default
  - fix the message signature and verification tool to produce proper eCash signed message
  - support label and card authenticity features
- Allow encrypting watch-only wallets and hardware wallets (#150).
- Add a tool to sign or broadcast multiple transactions from files (#152).
- Use the "m/44'/1'/0'" BIP44 derivation path by default in testnet mode (#153).
- Set up automatic code formatting and quality control tools (#141).


## Release 5.0.2

- Fix support for the `ectest:` address prefix and the `--testnet` command-line option.
- Change the message signature prefix to "eCash Signed Message:" (previously was "Bitcoin Signed Message:").
- Lower the default transaction fee from 5 satoshis/byte to 2 satoshis/byte.
- Links `ecash:` URI's to Electrum ABC on Windows and Mac OS.
- Use `ecash:` addresses (without prefix) in URL for BlockChair's explorer.
- Don't encourage users to open issues on Electrum ABC's GitHub repo when errors happen in external plugin code.
- Remove mentions of "Bitcoin Cash addresses" in the wallet creation wizard.
- Electron Cash backports:
  - Option to spend only fused coins on the spend tab
  - Updates for build scripts.


## Release 5.0.1

- Fix the missing thousands separator when formatting amounts on Mac OS and Windows.
- Update the API for block explorers after the rebranding. Most block explorers now use the "ecash:" prefix for
  addresses. Some explorer changed their URLs.
- Fix an issue with the transaction details dialog splitting addresses and amounts over two lines when the "ecash:"
  prefix is shown in the address.
- Add CoinGecko's new eCash exchange rate for fiat amount conversion. The legacy BCHA exchange rate API is still
  supported because the new one does not provide historical data prior to July 2021.
- Add explorer.be.cash to the list of supported block explorers.
- Set explorer.bitcoinabc.org as the default block explorer.
- Electron Cash backports:
  - Increase CashFusion transaction fees for high tiers (https://github.com/Electron-Cash/Electron-Cash/pull/1984)


## Release 5.0.0

- Rebranding from BCHA to eCash (XEC).
- Change base unit from BCHA (100 000 000 satoshis) to XEC (100 satoshis).
- Change CashAddr prefix from "bitcoincash:" to "ecash:".
- Make the address conversion tool display 3 results: eCash address,
  BCH address and Legacy Bitcoin address.
- Interpret amounts as XEC in BIP21 payment URIs. Generate payment URIs and
  QR codes with amounts in XEC.
- Add a scanner for usual eCash, BCH or BTC derivation paths to assist users
  when restoring a wallet from seed (feature backported from Electron Cash).


## Release 4.3.3

- Support restoring wallets from BIP39 word lists in other languages than
  english. New seeds phrases are still generated in english, because most
  other wallets only support english.
- Use the new derivation path `m/44'/899'/0` by default when creating or
  restoring a wallet. This is a pre-filled parameter that can be modified
  by the user. The BCH and BTC derivations paths are shown in a help
  message for users who wish to restore pre-fork wallets.
- Prefer sending confirmed coins when sending a transaction. Unconfirmed coins
  can still be used when necessary or when they are manually selected.
- Display a warning when sending funds to a legacy BTC address.
- Update some default configuration parameters the first time the user runs
  a new version of Electrum ABC (default fee, default CashFusion server).
- Display localized amounts with thousands separators to improve readability
  when switching the unit to mBCHA or bits.
- Always show the prefix when displaying a CashAddr in the user interface.
  This will prevent confusion when the prefix is changed, in the future.
- Support arbitrary CashAddr prefixes for the address conversion tool.
- Improvements to the Satochip plugin:
  - use BIP39 seeds by default instead of electrum seeds.
  - 2FA config is removed from initial setup, and can be activated from the
    option menu instead (clicking on the Satochip logo on the lower right
    corner).
  - PIN can have a maximum length of 16, not 64.
- Add a menu action in the Coins tab to export data for selected UTXOs to a
  JSON file.
- Use satoshis as a unit for amounts when generating payment URIs and QR codes.
  This aligns Electrum ABC with CashTab, Stamp and Cashew.
- Lower the default transaction fee from 10 satoshis/byte to 5 satoshis/byte.
- Minor performance improvements when freezing coins and saving wallet files.


## Release 4.3.2

- Decrease the default transaction fee from 80 satoshis/byte to 10 sats/byte
- Add an option in the 'Pay to' context menu to scan the current screen
  for a QR code.
- Add a documentation page [Contributing to Electrum ABC](CONTRIBUTING.md).
- Remove the deprecated CashShuffle plugin.
- Specify a default server for CashFusion.
- Fix a bug introduced in 4.3.1 when starting the program from the source
  package when the `secp256k1` library is not available. This bug did not
  affect the released binary files.
- Fix a bug related to the initial automatic copy of wallets from the
  Electron Cash data directory on Windows. The configuration paths were not
  changed accordingly, causing new wallets to be automatically saved in the
  Electron Cash directory.


## Release 4.3.1

- Fixed a bug happening when clicking on a server in the network overview
  dialog.
- Enable the fiat display again, using CoinGecko's price for BCHA.
- Add a checkpoint to ensure only BCHA servers can be used. When splitting
  coins, it is now recommended to run both Electrum ABC and Electron Cash.
- Improve the automatic importing of wallets and user settings from
  Electron Cash, for new users: clear fiat historic exchange rates to avoid
  displaying BCH prices for pre-fork transactions, clear the server blacklist
  and whitelist, copy also testnet wallets and settings.
- When creating a new wallet, always save the file in the standard user
  directory. Previously, wallets were saved in the same directory as the
  most recently opened wallet.
- Change the crash report window to redirect users to github in their
  web browser, with a pre-filled issue ready to be submitted.
- Fix a bug when attempting to interact with a Trezor T hardware wallet
  with the autolock feature enabled, when the device is locked.


## Release 4.3.0

 The first release is based on the
Electron Cash 4.2.0 codebase with the following changes

- updated list of electrum servers
- updated icons and branding
- use different directory for wallets and configuration
- automatically import wallets and some configuration files from Electron Cash
