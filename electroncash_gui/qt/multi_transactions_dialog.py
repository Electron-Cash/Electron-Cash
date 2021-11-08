import json
from pathlib import Path
from typing import Sequence

from PyQt5 import QtCore, QtWidgets

from electroncash import Transaction
from electroncash.constants import XEC
from electroncash.wallet import Abstract_Wallet


class MultiTransactionsWidget(QtWidgets.QWidget):
    """Display multiple transactions, with statistics and tools (sign, broadcast...)"""

    def __init__(self, wallet, main_window, parent=None):
        super().__init__(parent)
        self.wallet: Abstract_Wallet = wallet
        self.transactions: Sequence[Transaction] = []
        self.main_window = main_window

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

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

        self.save_button = QtWidgets.QPushButton("Save")
        buttons_layout.addWidget(self.save_button)
        self.sign_button = QtWidgets.QPushButton("Sign")
        buttons_layout.addWidget(self.sign_button)
        self.broadcast_button = QtWidgets.QPushButton("Broadcast")
        buttons_layout.addWidget(self.broadcast_button)
        self.disable_buttons()

        self.save_button.clicked.connect(self.on_save_clicked)
        self.sign_button.clicked.connect(self.on_sign_clicked)
        self.broadcast_button.clicked.connect(self.on_broadcast_clicked)

    def reset_labels(self):
        self.num_tx_label.setText("Number of transactions:")
        self.num_in_label.setText("Number of inputs per tx:")
        self.in_value_label.setText("Input value:")
        self.out_value_label.setText("Output value:")
        self.fees_label.setText("Fees:")

    def disable_buttons(self):
        self.save_button.setEnabled(False)
        self.sign_button.setEnabled(False)
        self.broadcast_button.setEnabled(False)

    def set_displayed_number_of_transactions(self, num_tx: int):
        """This method can be called to set the number of transactions without
        actually setting the transactions. It cen be used to demonstrate that progress
        is being made while transactions are still being built."""
        self.num_tx_label.setText(f"Number of transactions: <b>{num_tx}</b>")

    def set_transactions(self, transactions: Sequence[Transaction], can_sign: bool):
        """Enable buttons, compute and display some information about transactions."""
        self.transactions = transactions

        # Reset buttons when fresh unsigned transactions are set
        self.save_button.setText("Save")
        self.save_button.setEnabled(True)
        self.sign_button.setEnabled(can_sign)
        self.broadcast_button.setEnabled(False)

        self.num_tx_label.setText(f"Number of transactions: <b>{len(transactions)}</b>")

        # Assume the first transactions has the maximum number of inputs
        num_in = 0 if len(transactions) == 0 else len(transactions[0].inputs())
        self.num_in_label.setText(f"Number of inputs per tx: <b>{num_in}</b>")

        in_value = sum([tx.input_value() for tx in transactions]) / 100
        out_value = sum([tx.output_value() for tx in transactions]) / 100
        fees = sum([tx.get_fee() for tx in transactions]) / 100
        self.in_value_label.setText(f"Input value: <b>{in_value} {XEC}</b>")
        self.out_value_label.setText(f"Output value: <b>{out_value} {XEC}</b>")
        self.fees_label.setText(f"Fees: <b>{fees} {XEC}</b>")

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
        password = None
        if self.wallet.has_password():
            password = self.main_window.password_dialog(
                "Enter your password to proceed"
            )
            if not password:
                return

        for tx in self.transactions:
            self.wallet.sign_transaction(tx, password, use_cache=True)

        QtWidgets.QMessageBox.information(
            self,
            "Done signing",
            f"Signed {len(self.transactions)} transactions. Remember to save them!",
        )

        # Signing is done in a different thread, so delay the check for completeness
        # until the signatures have been added to the transaction.
        QtCore.QTimer.singleShot(
            2000,
            lambda: self.broadcast_button.setEnabled(
                self.transactions[-1].is_complete()
            ),
        )
        self.save_button.setText("Save (signed)")

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
