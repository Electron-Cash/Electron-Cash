package org.electroncash.electroncash3

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.SeekBar
import android.widget.Spinner
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel
import com.chaquo.python.Kwarg
import com.chaquo.python.PyException
import com.chaquo.python.PyObject
import com.chaquo.python.PyObject.fromJava
import com.google.zxing.integration.android.IntentIntegrator
import org.electroncash.electroncash3.databinding.SendBinding
import kotlin.math.pow


val libPaymentRequest by lazy { libMod("paymentrequest") }
val libStorage by lazy { libMod("storage") }

val MIN_FEE = 1  // sat/byte


class SendDialog : TaskLauncherDialog<Unit>() {
    private var _binding: SendBinding? = null
    private val binding get() = _binding!!

    val wallet = daemonModel.wallet!!

    class Model : ViewModel() {
        var paymentRequest: PyObject? = null
        val tx = BackgroundLiveData<TxArgs, TxResult>().apply {
            notifyIncomplete = false  // Only notify transactions which match the UI state.
            function = { it.invoke() }
        }
        var tokenSend: Boolean = false
        var hasNfts: Boolean = false
        var hasFts: Boolean = false
    }
    val model: Model by viewModels()

    class LabelWithId(val label: String, val id: String) {
        override fun toString(): String {
            return label
        }
    }

    // This is currently used by the sweep private keys command. In the future it could also be
    // used for coin selection.
    val inputs by lazy {
        val inputsStr = arguments?.getString("inputs")
        if (inputsStr == null) null
        else literalEval(inputsStr)!!.also {
            for (i in it.asList()) {
                val iMap = i.asMap()
                iMap[fromJava("address")] = makeAddress(iMap[fromJava("address")].toString())
            }
        }
    }

    // The "unbroadcasted" flag controls whether the dialog opens as "Send" (false) or
    // "Sign" (true). m-of-n multisig wallets where m >= 2 will also open the dialog
    // as "Sign", because their transactions can't be broadcast after a single signature.
    val unbroadcasted by lazy {
        if (arguments != null && arguments!!.containsKey("unbroadcasted")) {
            arguments!!.getBoolean("unbroadcasted")
        } else {
            val multisigType = libStorage.callAttr("multisig_type", daemonModel.walletType)
                ?.toJava(IntArray::class.java)
            multisigType != null && multisigType[0] != 1
        }
    }

    // Whether or not the dialog started up as a bch send or token send dialog
    // (model.tokenSend reflects the current state)
    val initialTokenSend by lazy {
        if (arguments != null && arguments!!.containsKey("token_send")) {
            arguments!!.getBoolean("token_send")
        } else {
            false
        }
    }

    val readOnly by lazy {
        arguments != null &&
            (arguments!!.containsKey("txHex") || arguments!!.containsKey("sweepKeypairs"))
    }

    lateinit var amountBox: AmountBox
    var settingAmount = false  // Prevent infinite recursion.
    private lateinit var description: String

    init {
        // The SendDialog shouldn't be dismissed until the SendPasswordDialog succeeds.
        dismissAfterExecute = false

        if (daemonModel.wallet!!.callAttr("is_watching_only").toBoolean()) {
            throw ToastException(R.string.this_wallet_is)
        } else if (daemonModel.wallet!!.callAttr("get_receiving_addresses")
                   .asList().isEmpty()) {
            // At least one receiving address is needed to call wallet.dummy_address.
            throw ToastException(
                R.string.electron_cash_is_generating_your_addresses__please_wait_)
        }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        _binding = SendBinding.inflate(LayoutInflater.from(context))
        buildCategorySpinner()
        buildNftSpinner()
        if (!unbroadcasted) {
            builder.setPositiveButton(R.string.send, null)
        } else {
            builder.setTitle(R.string.sign_transaction)
                .setPositiveButton(R.string.sign, null)
            binding.tvTitle.visibility = View.GONE
            binding.header.removeView(binding.spnCoinType)
            binding.sendRow.addView(binding.spnCoinType)
            binding.sendRow.visibility = View.VISIBLE
        }
        builder.setView(binding.root)
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.scan_qr, null)
    }

    private fun buildCategorySpinner() {
        val categoryLabels = getCategoryOptions()
        val spnAdapter = ArrayAdapter(context!!, android.R.layout.simple_spinner_dropdown_item,
                                      categoryLabels)
        binding.spnCategory.setAdapter(spnAdapter)
        binding.spnCategory.onItemSelectedListener = object :
            AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?,
                                        position: Int, id: Long) {
                val category = getSelectedCategory()
                val nftLabels = getNftOptions(category)
                val newAdapter = ArrayAdapter(
                    context!!, android.R.layout.simple_spinner_dropdown_item, nftLabels)
                binding.spnNft.setAdapter(newAdapter)
                model.hasNfts = nftLabels.size > 1
                var fungibles = "0"
                category?.let {
                    fungibles = it.fungibles
                }
                model.hasFts = fungibles != "0"
                binding.etFtAmount.setText("")
                val decimals = if (category == null) 0 else {
                    guiTokens.callAttr("get_token_decimals", category.id).toInt()
                }
                var hint = "0"
                if (decimals > 0) {
                    hint += "." + "0".repeat(decimals)
                }
                binding.etFtAmount.setHint(hint)
                refreshTx()
                updateUI()

            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    class Category(val id: String, val name: String, val fungibles: String,
                   val nfts: ArrayList<NFT>)

    private fun getCategoryOptions(): ArrayList<LabelWithId> {
        val options = ArrayList<LabelWithId>()
        options.add(LabelWithId(getString(R.string.please_select), ""))
        val tokens = guiTokens.callAttr("get_tokens", wallet)!!
        for (token in tokens.asList()) {
            val tokenMap: Map<String, PyObject> = token.asMap().mapKeys { it.key.toString() }
            val tokenName = tokenMap["tokenName"].toString()
            val tokenId = tokenMap["tokenId"].toString()
            options.add(LabelWithId(tokenName, tokenId))
        }
        return options
    }

    private fun getSelectedCategory(): Category? {
        val selectedOption = binding.spnCategory.selectedItem as LabelWithId
        val categoryId = selectedOption.id
        return getCategoriesDetails(categoryId)[categoryId]
    }

    private fun getNftOptions(category: Category?): ArrayList<LabelWithId> {
        val options = ArrayList<LabelWithId>()
        options.add(LabelWithId(getString(R.string.none), ""))
        category?.let {
            for (nft in it.nfts) {
                options.add(LabelWithId(nft.label, nft.utxoId))
            }
        }
        return options
    }

    private fun getCategoriesDetails(categoryIdFilter: String = ""): HashMap<String, Category> {
        val categories = HashMap<String, Category>()
        val tokens = guiTokens.callAttr("get_tokens", wallet,
                                        Kwarg("category_id_filter", categoryIdFilter))!!
        for (token in tokens.asList()) {
            val tokenMap: Map<String, PyObject> = token.asMap().mapKeys { it.key.toString() }
            val categoryId = tokenMap["tokenId"].toString();
            val nftList = tokenMap["nftDetails"]!!.asList().map { it.asList().map{ it.toString() } }
            val nfts = ArrayList<NFT>()
            for (nft in nftList) {
                nfts.add(NFT(nft[0], nft[1], nft[2]))
            }
            val category = Category(
                categoryId,
                tokenMap["name"].toString(),
                tokenMap["amount"]!!.toString(),
                nfts)
            categories[categoryId] = category
        }
        return categories
    }

    private fun buildNftSpinner() {
        val nftArray = ArrayList<String>()
        val spnAdapter = ArrayAdapter(context!!, android.R.layout.simple_spinner_dropdown_item,
                                      nftArray)
        binding.spnNft.setAdapter(spnAdapter)
        binding.spnNft.onItemSelectedListener = object :
            AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?,
                                        position: Int, id: Long) {
                refreshTx()
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    private fun setMaxFungibleAmount() {
        val category = getSelectedCategory()
        var amount: String = "0"
        category?.let {
            amount = it.fungibles
        }
        try {
            settingAmount = true
            binding.etFtAmount.setText(amount)
            binding.etFtAmount.setSelection(binding.etFtAmount.text.length)
        } finally {
            settingAmount = false
        }
    }

    override fun onShowDialog() {
        super.onShowDialog()
        binding.etAddress.addAfterTextChangedListener { s: Editable ->
            val scheme = libNetworks.get("net")!!.get("CASHADDR_PREFIX")!!.toString()
            if (s.startsWith(scheme + ":")) {
                onUri(s.toString())
            } else {
                refreshTx()
            }
        }

        amountBox = AmountBox(binding.incAmount)
        amountBox.listener = {
            if (!settingAmount) {
                binding.btnMax.isChecked = false
                refreshTx()
            }
        }
        setPaymentRequest(model.paymentRequest)
        binding.btnMax.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                setAmount(null)
            }
            refreshTx()
        }

        binding.etFtAmount.addAfterTextChangedListener {
            if (!settingAmount) {
                binding.btnFtMax.isChecked = false
            }
            refreshTx()
        }
        binding.btnFtMax.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                setMaxFungibleAmount()
            }
            refreshTx()
        }

        with (binding.sbFee) {
            // setMin is not available until API level 26, so values are offset by MIN_FEE.
            progress = (daemonModel.config.callAttr("fee_per_kb").toInt() / 1000) - MIN_FEE
            max = (daemonModel.config.callAttr("max_fee_rate").toInt() / 1000) - MIN_FEE
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                var tracking = false  // Avoid flickering while tracking.

                override fun onProgressChanged(seekBar: SeekBar, progress: Int,
                                               fromUser: Boolean) {
                    settings.getInt("fee_per_kb").setValue(feeSpb * 1000)
                    setFeeLabel()
                    if (!tracking) {  // Maybe the value can be changed without a touch.
                        refreshTx()
                    }
                }
                override fun onStartTrackingTouch(seekBar: SeekBar) {
                    tracking = true
                }
                override fun onStopTrackingTouch(seekBar: SeekBar) {
                    tracking = false
                    refreshTx()
                }
            })
        }
        setFeeLabel()

        // If this is the final signature, the user will be given a chance to set the
        // description in the SignedTransactionDialog.
        if (unbroadcasted) {
            hideDescription(this, binding.tvDescriptionLabel, binding.etDescription)
        }

        val txHex = arguments?.getString("txHex")
        if (txHex != null) {
            val tx = txFromHex(txHex)
            model.tx.value = TxResult(tx)
            setLoadedTransaction(tx)
        }

        if (arguments?.getString("sweepKeypairs") != null) {
            binding.btnMax.isChecked = true

            // The inputs may be truncated to avoid exceeding the maximum transaction size,
            // Display the input count so the user knows to sweep again in that situation.
            dialog.setTitle(app.getQuantityString1(R.plurals.sweep_input,
                                                   inputs!!.asList().size))
        }

        if (readOnly) {
            binding.etAddress.isFocusable = false
             (binding.btnContacts as View).visibility = View.GONE
             amountBox.isEditable = false
             binding.btnMax.isEnabled = false
             dialog.getButton(AlertDialog.BUTTON_NEUTRAL).visibility = View.GONE
        }

        val spinner: Spinner = binding.spnCoinType
        ArrayAdapter.createFromResource(
            activity!!,
            R.array.coin_type,
            android.R.layout.simple_spinner_item
        ).also { adapter ->
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            spinner.adapter = adapter
        }
        spinner.setSelection(if (model.tokenSend) 1 else 0)
        spinner.onItemSelectedListener = object :
            AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>, view: View?,
                position: Int, id: Long
            ) {
                model.tokenSend = (position == 1)
                updateUI()
            }

            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
        updateUI()

        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
        model.tx.observe(this, Observer { onTx(it) })
    }

    override fun onFirstShowDialog() {
        if (arguments != null) {
            val address = arguments!!.getString("address")
            if (address != null) {
                binding.etAddress.setText(address)
                amountBox.requestFocus()
            }
        }
        model.tokenSend = initialTokenSend
        binding.spnCoinType.setSelection(if (model.tokenSend) 1 else 0)
        refreshTx()
    }

    private fun updateUI() {
        binding.tvAddressLabel.setText(if (model.tokenSend) R.string.Send_to else R.string.Pay_to)
        val showIf = fun(view: View, condition: Boolean) {
            view.visibility = if (condition) View.VISIBLE else View.GONE
        }
        showIf(binding.bchRow, !model.tokenSend)
        showIf(binding.categoryRow, model.tokenSend)
        showIf(binding.nftRow, model.tokenSend && model.hasNfts)
        showIf(binding.fungiblesRow, model.tokenSend && model.hasFts)
    }

    val feeSpb: Int
        get() = MIN_FEE + binding.sbFee.progress

    fun refreshTx() {
        if (arguments?.containsKey("txHex") != true) {
            val selectedCategory = binding.spnCategory.selectedItem as LabelWithId?
            val categoryId = selectedCategory?.id ?: ""
            val selectedNft = binding.spnNft.selectedItem as LabelWithId?
            val nftId = selectedNft?.id ?: ""
            val ftAmountStr = binding.etFtAmount.text.toString()
            model.tx.refresh(TxArgs(wallet, model.paymentRequest, binding.etAddress.text.toString(),
                amountBox.amount, binding.btnMax.isChecked, inputs,
                categoryId, ftAmountStr, nftId,
                model.tokenSend, model.hasNfts, model.hasFts, feeSpb * 1000))
        }
    }

    fun onTx(result: TxResult) {
        val tx = try {
            result.get()
        } catch (e: ToastException) {
            null  // Don't show it until the user clicks Send.
        }
        if (binding.btnMax.isChecked && tx != null) {
            setAmount(tx.callAttr("output_value").toLong())
        }
        setFeeLabel(tx)
    }

    fun setAmount(amount: Long?) {
        try {
            settingAmount = true
            amountBox.amount = amount
        } finally {
            settingAmount = false
        }
    }

    fun setAddress(address: String) {
        binding.etAddress.setText(address)
    }

    fun setFeeLabel(tx: PyObject? = null): Int {
        val fee = tx?.callAttr("get_fee")?.toInt()
        val spb = if (fee != null) fee / tx.callAttr("estimated_size").toInt()
                  else feeSpb
        var feeLabel = getString(R.string.sats_per, spb)
        if (fee != null) {
            feeLabel += " (${ltr(formatSatoshisAndUnit(fee.toLong()))})"
        }
        binding.tvFeeLabel.setText(feeLabel)
        return spb
    }

    enum class AddressType {
        CASH, TOKEN, DUMMY, PAYMENT_REQUEST
    }

    class TxArgs(val wallet: PyObject, val pr: PyObject?, val addrStr: String,
                 val amount: Long?, val max: Boolean, val inputs: PyObject?,
                 val categoryId: String, val fungibleAmountStr: String, val nft: String,
                 val isTokenSend: Boolean, val hasNfts: Boolean, val hasFts: Boolean,
                 val feePerKb: Int) {


        private fun getAddress(): Pair<PyObject, AddressType> {
            return try {
                val address = makeAddress(addrStr)
                val type = if (isTokenAddress(addrStr)) {
                    AddressType.TOKEN
                } else {
                    AddressType.CASH
                }
                Pair(address, type)
            } catch (e: ToastException) {
                Pair(wallet.callAttr("dummy_address"), AddressType.DUMMY)
            }
        }

        private fun hasFractionalFTs(amountStr: String, categoryId: String): Boolean {
            if (amountStr.toDoubleOrNull() !in setOf(null, 0.0)) {
                val amount = amountStr.toDouble()
                val decimals = guiTokens.callAttr("get_token_decimals", categoryId).toInt()
                val units = amount * 10.0.pow(decimals)
                val subunits = units % 1
                return subunits != 0.0
            }
            return false
        }

        fun invoke(): TxResult {
            return try {
                val addressType: AddressType
                val transaction: PyObject?
                if (isTokenSend) {
                    val hasFungible = fungibleAmountStr.toDoubleOrNull() !in setOf(null, 0.0)
                    if (categoryId.isEmpty()) {
                        return TxResult(ToastException(R.string.please_select_a))
                    } else if (nft.isEmpty() && !hasFungible) {
                        return TxResult(ToastException(
                            if (hasNfts && hasFts) {
                                R.string.please_choose_an
                            } else if (hasNfts) {
                                R.string.please_select_an
                            } else {
                                R.string.please_choose_a_fungible
                            }
                        ))
                    } else if (hasFractionalFTs(fungibleAmountStr, categoryId)) {
                        return TxResult(ToastException(R.string.too_many_fungible))
                    } else {
                        val (toAddress, type) = getAddress()
                        addressType = type
                        transaction = guiTokens.callAttr(
                            "make_tx", wallet, daemonModel.config, toAddress,
                            feePerKb, categoryId, fungibleAmountStr, nft
                        )
                    }
                } else {
                    val inputs = this.inputs ?: wallet.callAttr(
                        "get_spendable_coins", null, daemonModel.config,
                        Kwarg("isInvoice", pr != null)
                    )
                    val fusion = daemonModel.daemon.get("plugins")!!.callAttr("find_plugin", "fusion")
                    fusion.callAttr("spendable_coin_filter", daemonModel.wallet, inputs)
                    val outputs: PyObject
                    if (pr != null) {
                        outputs = pr.callAttr("get_outputs")
                        addressType = AddressType.PAYMENT_REQUEST
                    } else {
                        if (amount == null && !max) {
                            return TxResult(ToastException(R.string.Invalid_amount))
                        }
                        val (toAddress, type) = getAddress()
                        addressType = type
                        val output = py.builtins.callAttr(
                            "tuple", arrayOf(
                                libBitcoin.get("TYPE_ADDRESS"), toAddress,
                                if (max) "!" else amount
                            )
                        )
                        outputs = py.builtins.callAttr("list", arrayOf(output))
                    }
                    transaction = wallet.callAttr(
                        "make_unsigned_transaction", inputs, outputs,
                        daemonModel.config, Kwarg("sign_schnorr", signSchnorr())
                    )
                }
                TxResult(transaction, addressType)
            } catch (e: PyException) {
                TxResult(if (e.message!!.startsWith("NotEnoughFunds"))
                         ToastException(R.string.insufficient_funds) else e)
            }
        }
    }

    class TxResult(val tx: PyObject?, val addressType: AddressType = AddressType.CASH,
                   val error: Throwable? = null) {
        constructor(error: Throwable) : this(null, AddressType.TOKEN, error)
        fun get() = tx ?: throw error!!
    }

    // Receives the result of a QR scan.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            onUri(result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onUri(uri: String) {
        try {
            if (readOnly) {
                throw ToastException(R.string.cannot_process)
            }

            val parsed: PyObject
            try {
                parsed = libWeb.callAttr("parse_URI", uri)!!
            } catch (e: PyException) {
                throw ToastException(e)
            }

            val r = parsed.callAttr("get", "r")
            if (r != null) {
                showDialog(this, GetPaymentRequestDialog(r.toString()))
            } else {
                setPaymentRequest(null)
                parsed.callAttr("get", "address")?.let { binding.etAddress.setText(it.toString()) }
                parsed.callAttr("get", "message")?.let { binding.etDescription.setText(it.toString()) }
                parsed.callAttr("get", "amount")?.let {
                    try {
                        amountBox.amount = it.toLong()
                    }  catch (e: PyException) {
                        throw if (e.message!!.startsWith("OverflowError")) ToastException(e)
                        else e
                    }
                }
                amountBox.requestFocus()
                binding.btnMax.isChecked = false
            }
        } catch (e: ToastException) {
            e.show()
        }
    }

    fun setPaymentRequest(pr: PyObject?) {
        model.paymentRequest = pr
        for (et in listOf(binding.etAddress, binding.etDescription)) {
            setEditable(et, (pr == null))
        }
        amountBox.isEditable = (pr == null)
        binding.btnMax.isEnabled = (pr == null)

        if (pr != null) {
            binding.etAddress.setText(pr.callAttr("get_requestor").toString())
            amountBox.amount = pr.callAttr("get_amount").toLong()
            binding.btnMax.isChecked = false
            binding.etDescription.setText(pr.callAttr("get_memo").toString())
        }

        binding.btnContacts.setImageResource(if (pr == null) R.drawable.ic_person_24dp
                                     else R.drawable.ic_check_24dp)
        binding.btnContacts.setOnClickListener {
            if (pr == null) {
                showDialog(this, SendContactsDialog())
            } else {
                toast(pr.callAttr("get_verify_status").toString())
            }
        }
    }

    /**
     * Fill in the Send dialog with data from a loaded transaction.
     */
    fun setLoadedTransaction(tx: PyObject) {
        val spb = setFeeLabel(tx)
        binding.sbFee.setOnSeekBarChangeListener(null)  // Avoid persisting to settings.
        binding.sbFee.progress = spb - MIN_FEE
        binding.sbFee.isEnabled = false

        // Try to guess which outputs are the intended recipients. Where possible, this should
        // display the same values that were entered when the transaction was created.
        val wallet = daemonModel.wallet!!
        val outputs = tx.callAttr("outputs").asList()
        var recipients = filterOutputs(outputs, wallet, "is_mine")
        if (recipients.isEmpty()) {
            // All outputs are mine. Try only receiving addresses.
            recipients = filterOutputs(outputs, wallet, "is_change")
        }
        if (recipients.isEmpty()) {
            // All outputs are change.
            recipients = outputs
        }

        // If there is only one recipient, their address will be displayed.
        // Otherwise, this is a "pay to many" transaction.
        if (recipients.size == 1) {
            binding.etAddress.setText(recipients[0].asList()[1].toString())
        } else {
            binding.etAddress.setText(R.string.pay_to_many)
        }
        setAmount(recipients.map { it.asList()[2].toLong() }.sum())
    }

    private fun filterOutputs(outputs: List<PyObject>, wallet: PyObject, methodName: String) =
        outputs.filter { !wallet.callAttr(methodName, it.asList()[1]).toBoolean() }

    override fun onPreExecute() {
        description = binding.etDescription.text.toString()
    }

    override fun doInBackground() {
        model.tx.waitUntilComplete()
        val keypairsStr = arguments?.getString("sweepKeypairs")
        if (keypairsStr != null) {
            val tx = model.tx.value!!.get()
            tx.callAttr("sign", literalEval(keypairsStr))
            broadcastTransaction(wallet, tx, description)
        }
    }

    override fun onPostExecute(result: Unit) {
        if (arguments != null && arguments!!.containsKey("sweepKeypairs")) {
            toast(if (model.tokenSend) R.string.tokens_sent else R.string.payment_sent)
            closeDialogs(this)
        } else {
            try {
                // Verify the transaction is valid before asking for a password.
                val txResult = model.tx.value!!
                when (txResult.addressType) {
                    AddressType.CASH -> if (model.tokenSend) throw ToastException(R.string.not_a_cashtoken)
                    AddressType.DUMMY -> throw ToastException(R.string.Invalid_address)
                    AddressType.TOKEN -> {}
                    AddressType.PAYMENT_REQUEST -> {}
                }
                txResult.get()   // May throw ToastException.
                showDialog(this, SendPasswordDialog().apply { arguments = Bundle().apply {
                    putString("description", this@SendDialog.binding.etDescription.text.toString())
                }})
            } catch (e: ToastException) { e.show() }
        }
    }
}


class GetPaymentRequestDialog() : TaskDialog<PyObject>() {
    val sendDialog by lazy { targetFragment as SendDialog }

    constructor(url: String) : this() {
        arguments = Bundle().apply { putString("url", url) }
    }

    override fun doInBackground(): PyObject {
        val pr = libPaymentRequest.callAttr("get_payment_request",
                                            arguments!!.getString("url")!!)!!
        if (!pr.callAttr("verify", sendDialog.wallet.get("contacts")!!).toBoolean()) {
            throw ToastException(pr.get("error").toString())
        }
        checkExpired(pr)
        return pr
    }

    override fun onPostExecute(result: PyObject) {
        sendDialog.setPaymentRequest(result)
    }
}


class SendContactsDialog : MenuDialog() {
    private var _binding: SendBinding? = null

    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = SendBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    val sendDialog by lazy { targetFragment as SendDialog }
    val contacts: List<PyObject> by lazy {
        val typeFilter = if (sendDialog.model.tokenSend) 2 else 0
        guiContacts.callAttr("get_contacts", sendDialog.wallet, typeFilter).asList()
    }
    val hasAnyContacts: Boolean by lazy {
        guiContacts.callAttr("get_contacts", sendDialog.wallet, 0).asList().isNotEmpty()
    }

    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        builder.setTitle(R.string.contacts)
        contacts.forEachIndexed { i, contact ->
            menu.add(Menu.NONE, i, Menu.NONE, contact.get("name").toString())
        }
    }

    override fun onShowDialog() {
        if (contacts.isEmpty()) {
            toast (if (hasAnyContacts) {
                R.string.you_dont_have_any_token
            } else {
                R.string.you_dont_have_any_contacts
            })
            dismiss()
        }
    }

    override fun onMenuItemSelected(item: MenuItem) {
        val contact = contacts[item.itemId]
        val addressFormat = if (contact["type"].toString() == "tokenaddr") {
            "to_token_string"
        } else {
            "to_ui_string"
        }
        val address = makeAddress(contact["address"].toString())
        with (sendDialog) {
            setAddress(address.callAttr(addressFormat).toString())
            amountBox.requestFocus()
        }
    }
}


class SendPasswordDialog : PasswordDialog<Unit>() {
    val sendDialog by lazy { targetFragment as SendDialog }
    val tx: PyObject by lazy { sendDialog.model.tx.value!!.get() }

    override fun onPassword(password: String) {
        val wallet = sendDialog.wallet
        wallet.callAttr("sign_transaction", tx, password)
        if (!sendDialog.unbroadcasted) {
            val pr = sendDialog.model.paymentRequest
            val broadcastFunc: ((PyObject) -> PyObject)? =
                if (pr == null) null
                else { tx ->
                    checkExpired(pr)
                    val refundAddr = wallet.callAttr("get_receiving_addresses").asList().get(0)
                    pr.callAttr("send_payment", tx.toString(), refundAddr)
                }
            broadcastTransaction(wallet, tx, arguments!!.getString("description")!!,
                                 broadcastFunc)
        }
    }

    override fun onPostExecute(result: Unit) {
        closeDialogs(sendDialog)
        if (!sendDialog.unbroadcasted) {
            toast(if (sendDialog.model.tokenSend) R.string.tokens_sent else R.string.payment_sent, Toast.LENGTH_SHORT)
        } else {
            showDialog(this, SignedTransactionDialog().apply { arguments = Bundle().apply {
                putString("txHex", tx.toString())
            }})
        }
    }
}


private fun checkExpired(pr: PyObject) {
    if (pr.callAttr("has_expired").toBoolean()) {
        throw ToastException(R.string.payment_request_has)
    }
}


fun broadcastTransaction(wallet: PyObject, tx: PyObject, description: String,
                         broadcastFunc: ((PyObject) -> PyObject)? = null) {
    daemonModel.assertConnected()
    val result = if (broadcastFunc != null) {
        broadcastFunc(tx)
    } else {
        daemonModel.network.callAttr("broadcast_transaction", tx)
    }
    if (!result.asList().get(0).toBoolean()) {
        var message = result.asList().get(1).toString()
        message = message.replace(Regex("^error: (.*)"), "$1")
        throw ToastException(message)
    }

    setDescription(wallet, tx.callAttr("txid").toString(), description)
}


fun literalEval(str: String): PyObject? =
    py.getModule("ast").callAttr("literal_eval", str)
