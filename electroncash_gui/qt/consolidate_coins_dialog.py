import json
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

from PyQt5 import QtCore, QtWidgets

from electroncash.address import Address, AddressError
from electroncash.consolidate import (
    MAX_STANDARD_TX_SIZE,
    MAX_TX_SIZE,
    AddressConsolidator,
)
from electroncash.constants import PROJECT_NAME, XEC
from electroncash.transaction import Transaction
from electroncash.wallet import Abstract_Wallet
from electroncash_gui.qt.util import MessageBoxMixin


class TransactionsStatus(Enum):
    NOT_STARTED = "not started"
    SELECTING = "selecting coins..."
    BUILDING = "building transactions..."
    FINISHED = "finished building transactions"
    NO_RESULT = "finished without generating any transactions"


class ConsolidateWorker(QtCore.QObject):
    finished = QtCore.pyqtSignal()
    status_changed = QtCore.pyqtSignal(TransactionsStatus)
    transactions_ready = QtCore.pyqtSignal(list)

    def __init__(
        self,
        address: Address,
        wallet: Abstract_Wallet,
        include_coinbase: bool,
        include_non_coinbase: bool,
        include_frozen: bool,
        include_slp: bool,
        minimum_value: Optional[int],
        maximum_value: Optional[int],
        output_address: Address,
        max_tx_size: int,
    ):
        super().__init__()
        self.status_changed.emit(TransactionsStatus.SELECTING)
        self.consolidator = AddressConsolidator(
            address,
            wallet,
            include_coinbase,
            include_non_coinbase,
            include_frozen,
            include_slp,
            minimum_value,
            maximum_value,
        )
        self.output_address = output_address
        self.max_tx_size = max_tx_size

    def build_transactions(self):
        self.status_changed.emit(TransactionsStatus.BUILDING)
        transactions = self.consolidator.get_unsigned_transactions(
            self.output_address,
            self.max_tx_size,
        )
        if transactions:
            self.status_changed.emit(TransactionsStatus.FINISHED)
            # else the transaction page will set the status to NO_RESULT upon receiving
            # an empty list of transactions
        self.transactions_ready.emit(transactions)
        self.finished.emit()


class ConsolidateCoinsWizard(QtWidgets.QWizard, MessageBoxMixin):
    def __init__(
        self,
        address: Address,
        wallet: Abstract_Wallet,
        main_window,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(
            f"Consolidate coins for address {address.to_full_ui_string()}"
        )

        self.address: Address = address
        self.wallet: Abstract_Wallet = wallet
        self.transactions: Sequence[Transaction] = []
        self.main_window = main_window

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
            # run the coin consolidation in a separate thread
            self.thread = QtCore.QThread()
            self.worker = ConsolidateWorker(
                self.address,
                self.wallet,
                self.coins_page.include_coinbase_cb.isChecked(),
                self.coins_page.include_non_coinbase_cb.isChecked(),
                self.coins_page.include_frozen_cb.isChecked(),
                self.coins_page.include_slp_cb.isChecked(),
                self.coins_page.get_minimum_value(),
                self.coins_page.get_maximum_value(),
                self.output_page.get_output_address(),
                self.output_page.tx_size_sb.value(),
            )
            # Connections
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.build_transactions)
            self.worker.status_changed.connect(self.tx_page.update_status)
            self.worker.transactions_ready.connect(self.on_build_transactions_finished)
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)

            self.tx_page.display_work_in_progress()
            self.thread.start()

    def on_build_transactions_finished(self, transactions: Sequence[Transaction]):
        self.transactions = transactions
        can_sign = self.wallet.can_sign(self.transactions[0])
        self.tx_page.set_unsigned_transactions(self.transactions, can_sign)

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
        QtWidgets.QMessageBox.information(
            self, "Done saving", f"Saved {len(self.transactions)} files to {dir}"
        )

    def on_sign_clicked(self):
        def sign_done(success):
            pass

        def cleanup():
            pass

        for tx in self.transactions:
            self.main_window.sign_tx(tx, sign_done, on_pw_cancel=cleanup)

        QtWidgets.QMessageBox.information(
            self,
            "Done signing",
            f"Signed {len(self.transactions)} transactions. Remember to save them!",
        )

        # Signing is done in a different thread, so delay the check for completeness
        # until the signatures have been added to the transaction.
        QtCore.QTimer.singleShot(
            2000,
            lambda: self.tx_page.broadcast_button.setEnabled(
                self.transactions[-1].is_complete()
            ),
        )
        self.tx_page.save_button.setText("Save (signed)")

    def on_broadcast_clicked(self):
        self.main_window.push_top_level_window(self)
        try:
            for tx in self.transactions:
                self.main_window.broadcast_transaction(tx, None)
        finally:
            self.main_window.pop_top_level_window(self)
        QtWidgets.QMessageBox.information(
            self,
            "Done broadcasting",
            f"Broadcasted {len(self.transactions)} transactions.",
        )


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
        tx_size_layout.addWidget(QtWidgets.QLabel("Maximum transaction size (bytes)"))
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
        self.status: TransactionsStatus = TransactionsStatus.NOT_STARTED
        self.setTitle("Transactions")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        self.status_label = QtWidgets.QLabel()
        layout.addWidget(self.status_label)

        self.num_tx_label = QtWidgets.QLabel()
        layout.addWidget(self.num_tx_label)
        self.num_in_label = QtWidgets.QLabel()
        layout.addWidget(self.num_in_label)
        self.in_value_label = QtWidgets.QLabel()
        layout.addWidget(self.in_value_label)
        self.out_value_label = QtWidgets.QLabel()
        layout.addWidget(self.out_value_label)
        self.fees_label = QtWidgets.QLabel()
        layout.addWidget(self.fees_label)
        self.reset_labels()

        layout.addStretch(1)

        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)

        self.save_button = QtWidgets.QPushButton("Save (unsigned)")
        buttons_layout.addWidget(self.save_button)

        self.sign_button = QtWidgets.QPushButton("Sign")
        buttons_layout.addWidget(self.sign_button)

        self.broadcast_button = QtWidgets.QPushButton("Broadcast")
        self.broadcast_button.setEnabled(False)
        buttons_layout.addWidget(self.broadcast_button)

    def reset_labels(self):
        self.num_tx_label.setText("Number of transactions:")
        self.num_in_label.setText("Number of inputs per tx:")
        self.in_value_label.setText("Input value:")
        self.out_value_label.setText("Output value:")
        self.fees_label.setText("Fees:")

    def display_work_in_progress(self):
        """Disable buttons, inform the user about the ongoing computation"""
        self.reset_labels()
        self.save_button.setEnabled(False)
        self.sign_button.setEnabled(False)
        self.broadcast_button.setEnabled(False)
        self.setCursor(QtCore.Qt.WaitCursor)

    def update_status(self, status: TransactionsStatus):
        previous_status, self.status = self.status, status
        self.status_label.setText(f"Status: <b>{status.value}</b>")
        if previous_status != status and TransactionsStatus.FINISHED in [
            previous_status,
            status,
        ]:
            self.completeChanged.emit()

    def set_unsigned_transactions(
        self, transactions: Sequence[Transaction], can_sign: bool
    ):
        """Enable buttons, compute and display some information about transactions."""
        self.unsetCursor()
        if not transactions:
            self.update_status(TransactionsStatus.NO_RESULT)
            return
        # Reset buttons when fresh unsigned transactions are set
        self.save_button.setText("Save (unsigned)")
        self.save_button.setEnabled(True)
        self.sign_button.setEnabled(can_sign)
        self.broadcast_button.setEnabled(False)

        num_tx = len(transactions)
        self.num_tx_label.setText(f"Number of transactions: <b>{num_tx}</b>")

        # Assume the first transactions has the maximum number of inputs
        num_in = 0 if num_tx == 0 else len(transactions[0].inputs())
        self.num_in_label.setText(f"Maximum number of inputs per tx: <b>{num_in}</b>")

        in_value = sum([tx.input_value() for tx in transactions]) / 100
        out_value = sum([tx.output_value() for tx in transactions]) / 100
        fees = sum([tx.get_fee() for tx in transactions]) / 100
        self.in_value_label.setText(f"Input value: <b>{in_value} {XEC}</b>")
        self.out_value_label.setText(f"Output value: <b>{out_value} {XEC}</b>")
        self.fees_label.setText(f"Fees: <b>{fees} {XEC}</b>")

    def isComplete(self) -> bool:
        return self.status == TransactionsStatus.FINISHED
