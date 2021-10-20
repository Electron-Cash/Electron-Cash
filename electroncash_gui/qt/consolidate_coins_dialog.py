import json
from pathlib import Path
from typing import Optional, Sequence

from PyQt5 import QtWidgets

from electroncash.address import Address, AddressError
from electroncash.consolidate import (
    MAX_STANDARD_TX_SIZE,
    MAX_TX_SIZE,
    AddressConsolidator,
)
from electroncash.constants import PROJECT_NAME, XEC
from electroncash.transaction import Transaction
from electroncash.wallet import Abstract_Wallet


class ConsolidateCoinsWizard(QtWidgets.QWizard):
    def __init__(
        self,
        address: Address,
        wallet: Abstract_Wallet,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(
            f"Consolidate coins for address {address.to_full_ui_string()}"
        )

        self.address: Address = address
        self.wallet: Abstract_Wallet = wallet
        self.transactions: Sequence[Transaction] = []

        self.coins_page = CoinSelectionPage()
        self.addPage(self.coins_page)

        self.output_page = OutputsPage(address)
        self.addPage(self.output_page)

        self.tx_page = TransactionsPage()
        self.addPage(self.tx_page)
        self.tx_page.save_button.clicked.connect(self.on_save_clicked)
        self.tx_page.sign_button.clicked.connect(self.on_sign_clicked)
        self.tx_page.broadcast_button.clicked.connect(self.on_broadcast_clicked)

        self.currentIdChanged.connect(self.on_page_changed)

    def on_page_changed(self, page_id: int):
        if self.currentPage() is self.tx_page:
            consolidator = AddressConsolidator(
                self.address,
                self.wallet,
                self.coins_page.include_coinbase_cb.isChecked(),
                self.coins_page.include_non_coinbase_cb.isChecked(),
                self.coins_page.include_frozen_cb.isChecked(),
                self.coins_page.include_slp_cb.isChecked(),
                self.coins_page.get_minimum_value(),
                self.coins_page.get_maximum_value(),
            )
            self.transactions = consolidator.get_unsigned_transactions(
                self.output_page.get_output_address(),
                self.output_page.tx_size_sb.value(),
            )

    def on_save_clicked(self):
        dir = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select output directory for transaction files", str(Path.home())
        )
        if not dir:
            return
        for i, tx in enumerate(self.transactions):
            name = (
                f"signed_{i:03d}.txn" if tx.is_complete() else f"unsigned_{i:03d}.txn"
            )
            path = Path(dir) / name

            tx_dict = tx.as_dict()
            with open(path, "w+", encoding="utf-8") as f:
                f.write(json.dumps(tx_dict, indent=4) + "\n")

    def on_sign_clicked(self):
        pass

    def on_broadcast_clicked(self):
        pass


class CoinSelectionPage(QtWidgets.QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Filter coins")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        self.include_coinbase_cb = QtWidgets.QCheckBox("Include coinbase coins")
        self.include_coinbase_cb.setChecked(True)
        layout.addWidget(self.include_coinbase_cb)

        self.include_non_coinbase_cb = QtWidgets.QCheckBox("Include non-coinbase coins")
        self.include_non_coinbase_cb.setChecked(True)
        layout.addWidget(self.include_non_coinbase_cb)

        self.include_frozen_cb = QtWidgets.QCheckBox("Include frozen coins")
        self.include_frozen_cb.setChecked(False)
        layout.addWidget(self.include_frozen_cb)

        self.include_slp_cb = QtWidgets.QCheckBox("Include coins with SLP tokens")
        self.include_slp_cb.setChecked(False)
        self.include_slp_cb.toggled.connect(self.warn_burn_tokens)
        layout.addWidget(self.include_slp_cb)

        min_value_sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(min_value_sublayout)
        self.filter_by_min_value_cb = QtWidgets.QCheckBox(
            "Define a minimum value for coins to select"
        )
        self.filter_by_min_value_cb.setChecked(False)
        min_value_sublayout.addWidget(self.filter_by_min_value_cb)

        self.minimum_value_sb = QtWidgets.QDoubleSpinBox()
        self.minimum_value_sb.setEnabled(False)
        self.minimum_value_sb.setSingleStep(0.01)
        self.minimum_value_sb.setValue(0)
        self.minimum_value_sb.setToolTip(f"{XEC}")
        self.filter_by_min_value_cb.toggled.connect(self.minimum_value_sb.setEnabled)
        min_value_sublayout.addWidget(self.minimum_value_sb)

        max_value_sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(max_value_sublayout)
        self.filter_by_max_value_cb = QtWidgets.QCheckBox(
            "Define a maximum value for coins to select"
        )
        self.filter_by_max_value_cb.setChecked(False)
        max_value_sublayout.addWidget(self.filter_by_max_value_cb)

        self.maximum_value_sb = QtWidgets.QDoubleSpinBox()
        self.maximum_value_sb.setEnabled(False)
        self.maximum_value_sb.setSingleStep(0.01)
        self.maximum_value_sb.setMaximum(21_000_000_000_000)
        self.maximum_value_sb.setValue(21_000_000_000_000)
        self.maximum_value_sb.setToolTip(f"{XEC}")
        self.filter_by_max_value_cb.toggled.connect(self.maximum_value_sb.setEnabled)
        max_value_sublayout.addWidget(self.maximum_value_sb)

    def warn_burn_tokens(self, include_slp_is_checked: bool):
        if include_slp_is_checked:
            button = QtWidgets.QMessageBox.warning(
                self,
                "SLP tokens may be lost",
                f"{PROJECT_NAME} does not support transferring SLP tokens. If you "
                "include them in the consolidation transaction, they will be burned.",
                buttons=QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Ok,
            )
            if button == QtWidgets.QMessageBox.Cancel:
                self.include_slp_cb.setChecked(False)

    def get_minimum_value(self) -> Optional[int]:
        """Return minimum value in satoshis, or None"""
        return (
            None
            if not self.filter_by_min_value_cb.isChecked()
            else int(100 * self.minimum_value_sb.value())
        )

    def get_maximum_value(self) -> Optional[int]:
        """Return maximum value in satoshis, or None"""
        return (
            None
            if not self.filter_by_max_value_cb.isChecked()
            else int(100 * self.maximum_value_sb.value())
        )


class OutputsPage(QtWidgets.QWizardPage):
    def __init__(self, input_address: Address, parent=None):
        super().__init__(parent)

        self.inputs_address: Address = input_address
        self.output_address: Optional[Address] = None

        self.setTitle("Outputs")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        self.same_address_rb = QtWidgets.QRadioButton("Same address as inputs")
        self.same_address_rb.setChecked(True)
        layout.addWidget(self.same_address_rb)

        single_address_sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(single_address_sublayout)
        self.single_address_rb = QtWidgets.QRadioButton("Single address")
        single_address_sublayout.addWidget(self.single_address_rb)

        self.output_address_edit = QtWidgets.QLineEdit()
        self.output_address_edit.setPlaceholderText("enter a valid destination address")
        self.output_address_edit.setEnabled(False)
        single_address_sublayout.addWidget(self.output_address_edit)

        tx_size_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(tx_size_layout)
        tx_size_layout.addWidget(QtWidgets.QLabel("Maximum transaction size"))
        self.tx_size_sb = QtWidgets.QSpinBox()
        self.tx_size_sb.setMinimum(192)
        self.tx_size_sb.setMaximum(MAX_TX_SIZE)
        self.tx_size_sb.setValue(MAX_STANDARD_TX_SIZE)
        tx_size_layout.addWidget(self.tx_size_sb)

        self.single_address_rb.toggled.connect(self.output_address_edit.setEnabled)
        self.single_address_rb.toggled.connect(self.completeChanged.emit)
        self.output_address_edit.textChanged.connect(self.validate_address)

    def validate_address(self, address_text: str):
        previous_address = self.output_address
        try:
            self.output_address = Address.from_string(address_text)
        except AddressError:
            self.output_address = None
        if self.output_address != previous_address:
            self.completeChanged.emit()

    def isComplete(self):
        return not self.single_address_rb.isChecked() or self.output_address is not None

    def get_output_address(self) -> Address:
        return (
            self.inputs_address
            if self.same_address_rb.isChecked()
            else self.output_address
        )


class TransactionsPage(QtWidgets.QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Transactions")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        self.num_tx_label = QtWidgets.QLabel("Number of transactions:")
        layout.addWidget(self.num_tx_label)

        self.num_in_label = QtWidgets.QLabel("Average number of inputs per tx:")
        layout.addWidget(self.num_in_label)

        self.value_label = QtWidgets.QLabel("Input value: 0; Output value: 0; Fees: 0")
        layout.addWidget(self.num_tx_label)

        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)

        self.save_button = QtWidgets.QPushButton("Save")
        buttons_layout.addWidget(self.save_button)

        self.sign_button = QtWidgets.QPushButton("Sign")
        buttons_layout.addWidget(self.sign_button)

        self.broadcast_button = QtWidgets.QPushButton("Broadcast")
        self.broadcast_button.setEnabled(False)
        buttons_layout.addWidget(self.broadcast_button)

    def set_transactions(self, transactions: Sequence[Transaction]):
        self.reset_buttons()

        num_tx = len(self.transactions)
        self.num_tx_label.setText(f"Number of transactions: {num_tx}")

        avg_num_in = sum([len(tx.inputs()) for tx in transactions]) / num_tx
        self.num_in_label.setText(f"Average number of inputs per tx: {avg_num_in}")

        in_value = sum([tx.input_value() for tx in transactions]) / 100
        out_value = sum([tx.output_value() for tx in transactions]) / 100
        fees = sum([tx.get_fee() for tx in transactions]) / 100
        self.value_label.setText(
            f"Input value: {in_value} {XEC}; Output value: {out_value} {XEC}; Fees: {fees} {XEC}"
        )

    def reset_buttons(self):
        # FIXME: check the wallet's ability to sign and disable Sign if needed
        self.sign_button.setEnabled(True)
        self.broadcast_button.setEnabled(False)
