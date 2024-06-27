package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.fragment.app.replace
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import org.electroncash.electroncash3.databinding.RequestDetailBinding


class RequestsFragment : Fragment(R.layout.requests), MainFragment {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val spinner: Spinner = view.findViewById(R.id.spnReqType)
        ArrayAdapter.createFromResource(
            activity!!,
            R.array.request_type,
            android.R.layout.simple_spinner_item
        ).also { adapter ->
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            spinner.adapter = adapter
        }

        spinner.onItemSelectedListener = object :
            AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?,
                                        position: Int, id: Long) {
                when (position) {
                    0 -> replaceReqFragment<BchRequestsFragment>()
                    1 -> replaceReqFragment<TokenRequestsFragment>()
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    private inline fun <reified T : Fragment> replaceReqFragment() {
        requireActivity().supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace<T>(R.id.requests_container)
        }
    }
}


class RequestModel(wallet: PyObject, val request: PyObject) : ListItemModel(wallet) {
    val address by lazy { getField("address").toString() }
    val amount = getField("amount").toLong()
    val timestamp = formatTime(getField("time").toLong())
    val description = getField("memo").toString()
    val status = (app.resources.getStringArray(R.array.payment_status)
        [getField("status").toInt()])!!
    val tokenRequest = getNullableBooleanField("tokenreq")

    private fun getField(key: String): PyObject {
        return request.callAttr("get", key)!!
    }

    private fun getNullableBooleanField(key: String, default: Boolean = false): Boolean {
        val obj = request.callAttr("get", key)
        return obj?.toBoolean() ?: default
    }

    override val dialogArguments by lazy {
        Bundle().apply { putString("address", address) }
    }
}


class NewRequestDialog : TaskDialog<PyObject>() {
    val listFragment by lazy { targetFragment as ListFragment }

    override fun doInBackground(): PyObject {
        if (listFragment.wallet.callAttr("is_watching_only").toBoolean()) {
            throw ToastException(R.string.this_wallet_is)
        }
        return listFragment.wallet.callAttr("get_unused_address")
               ?: throw ToastException(R.string.no_more)
    }

    override fun onPostExecute(result: PyObject) {
        val tokenRequest = if (arguments != null && arguments!!.containsKey("token_request")) {
            arguments!!.getBoolean("token_request")
        } else {
            false
        }
        showDialog(listFragment, RequestDialog().apply { arguments = Bundle().apply {
            putString("address", result.callAttr("to_storage_string").toString())
            putBoolean("token_request", tokenRequest)
        }})
    }
}


class RequestDialog : DetailDialog() {
    private var _binding: RequestDetailBinding? = null
    private val binding get() = _binding!!

    val address by lazy {
        clsAddress.callAttr("from_string", arguments!!.getString("address"))!!
    }
    val existingRequest: PyObject? by lazy {
        wallet.callAttr("get_payment_request", address, daemonModel.config)
    }
    lateinit var amountBox: AmountBox

    // Whether or not this is a bch request or token request dialog
    val tokenRequest by lazy {
        if (arguments != null && arguments!!.containsKey("token_request")) {
            arguments!!.getBoolean("token_request")
        } else {
            false
        }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        _binding = RequestDetailBinding.inflate(LayoutInflater.from(context))

        with (builder) {
            setView(binding.root)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(R.string.save, null)
            if (existingRequest != null) {
                setNeutralButton(R.string.delete, null)
            }
        }
    }

    override fun onShowDialog() {
        amountBox = AmountBox(binding.incAmount)
        amountBox.listener = { updateUI() }

        binding.imgQR.setOnClickListener {
            copyToClipboard(getUri(), R.string.request_uri)
        }

        binding.tvAddress.setOnClickListener {
            copyToClipboard(binding.tvAddress.text, R.string.address)
        }

        binding.etDescription.addAfterTextChangedListener { updateUI() }
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }

        if (existingRequest != null) {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                showDialog(this, RequestDeleteDialog(address))
            }
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
        spinner.setSelection(if (tokenRequest) 1 else 0)
        spinner.onItemSelectedListener = object :
            AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>, view: View?,
                position: Int, id: Long
            ) {
                updateUI(position == 1)
            }

            override fun onNothingSelected(parent: AdapterView<*>) {}
        }

        updateUI(tokenRequest)
    }

    override fun onFirstShowDialog() {
        val request = existingRequest
        if (request != null) {
            val model = RequestModel(wallet, request)
            binding.spnCoinType.setSelection(if (model.tokenRequest) 1 else 0)
            amountBox.amount = model.amount
            binding.etDescription.setText(model.description)
        } else {
            amountBox.requestFocus()
        }
    }

    private fun isTokenRequest(): Boolean {
        return binding.spnCoinType.selectedItemPosition == 1
    }

    private fun updateUI(tokenRequest: Boolean = isTokenRequest()) {
        showQR(binding.imgQR, getUri())
        val addressFormat = if (tokenRequest) "to_token_string" else "to_ui_string"
        (binding.bchRow as View).visibility = if (tokenRequest) View.GONE else View.VISIBLE
        binding.tvAddress.text = address.callAttr(addressFormat).toString()
    }

    private fun getUri(): String {
        return libWeb.callAttr("create_URI", address, amountBox.amount, description,
                               Kwarg("token", isTokenRequest())).toString()
    }

    private fun onOK() {
        val amount = if (isTokenRequest()) 0 else amountBox.amount
        if (amount == null) {
            toast(R.string.Invalid_amount)
        } else {
            wallet.callAttr(
                "add_payment_request",
                wallet.callAttr("make_payment_request", address, amount, description,
                    Kwarg("token_request", isTokenRequest())),
                daemonModel.config, Kwarg("save", false))
            saveRequests(wallet)
            dismiss()

            // If the dialog was opened from the Transactions screen, we should now switch to
            // the Requests screen so the user can verify that the request has been saved.
            (activity as MainActivity).binding.navBottom.selectedItemId = R.id.navRequests
        }
    }

    val description
        get() = binding.etDescription.text.toString()
}


class RequestDeleteDialog() : AlertDialogFragment() {
    constructor(addr: PyObject) : this() {
        arguments = Bundle().apply {
            putString("address", addr.callAttr("to_storage_string").toString())
        }
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val requestDialog = targetFragment as RequestDialog
        val wallet = requestDialog.wallet
        builder.setTitle(R.string.confirm_delete)
            .setMessage(R.string.are_you_sure_you_wish_to_proceed)
            .setPositiveButton(R.string.delete) { _, _ ->
                wallet.callAttr("remove_payment_request",
                                makeAddress(arguments!!.getString("address")!!),
                                daemonModel.config, Kwarg("save", false))
                saveRequests(wallet)
                requestDialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


fun saveRequests(wallet: PyObject) {
    saveWallet(wallet) {
        wallet.callAttr("save_payment_requests", Kwarg("write", false))
    }
    daemonUpdate.setValue(Unit)
}