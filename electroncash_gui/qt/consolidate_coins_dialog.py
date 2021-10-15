from typing import Optional

from PyQt5 import QtWidgets

from electroncash.address import Address, AddressError

# from electroncash.consolidate import AddressConsolidator
from electroncash.wallet import Wallet


class ConsolidateCoinsWizard(QtWidgets.QWizard):
    def __init__(
        self,
        address: Address,
        wallet: Wallet,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(
            f"Consolidate coins for address {address.to_full_ui_string()}"
        )

        self.address = address

        self.coin_selection_page = CoinSelectionPage()
        self.addPage(self.coin_selection_page)

        self.pay_to_page = PayToPage()
        self.addPage(self.pay_to_page)


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

        self.include_slp_cb = QtWidgets.QCheckBox("Include SLP UTXOs")
        self.include_slp_cb.setChecked(False)
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
        self.filter_by_max_value_cb.toggled.connect(self.maximum_value_sb.setEnabled)
        max_value_sublayout.addWidget(self.maximum_value_sb)


class PayToPage(QtWidgets.QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._output_address: Optional[Address] = None

        self.setTitle("Pay to")

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

        self.single_address_rb.toggled.connect(self.output_address_edit.setEnabled)
        self.single_address_rb.toggled.connect(self.completeChanged.emit)
        self.output_address_edit.textChanged.connect(self.validate_address)

    def validate_address(self, address_text: str):
        previous_address = self._output_address
        try:
            self._output_address = Address.from_string(address_text)
        except AddressError:
            self._output_address = None
        if self._output_address != previous_address:
            self.completeChanged.emit()

    def isComplete(self):
        return (
            not self.single_address_rb.isChecked() or self._output_address is not None
        )
