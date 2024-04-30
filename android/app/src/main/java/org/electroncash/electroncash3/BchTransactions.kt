package org.electroncash.electroncash3

import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.content.res.AppCompatResources
import com.chaquo.python.PyObject
import org.electroncash.electroncash3.databinding.BchTransactionsBinding
import org.electroncash.electroncash3.databinding.TransactionDetailBinding
import kotlin.math.roundToInt


class BchTransactionsFragment : ListFragment(R.layout.bch_transactions, R.id.rvTransactions) {
    private var _binding: BchTransactionsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = BchTransactionsBinding.inflate(LayoutInflater.from(context))
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getString("base_unit"))
            data.function = { wallet.callAttr("get_history")!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnSend.setOnClickListener {
            try {
                showDialog(this, SendDialog())
            } catch (e: ToastException) { e.show() }
        }
        binding.btnRequest.setOnClickListener { showDialog(this, NewRequestDialog()) }
    }

    override fun onCreateAdapter() = TransactionsAdapter(this)
}


// Also used in AddressesTransactionsDialog.
fun TransactionsAdapter(listFragment: ListFragment) =
    ListAdapter(listFragment, R.layout.bch_transaction_list, ::TransactionModel,
                ::TransactionDialog)
        .apply { reversed = true }


class TransactionModel(wallet: PyObject, val txHistory: PyObject) : ListItemModel(wallet) {
    private fun get(key: String) = txHistory.get(key)

    val txid by lazy { get("tx_hash")!!.toString() }
    val amount by lazy { get("amount")?.toLong() ?: 0 }
    val balance by lazy { get("balance")?.toLong() ?: 0 }
    val timestamp by lazy { formatTime(get("timestamp")?.toLong()) }
    val label by lazy { getDescription(wallet, txid) }

    val icon: Drawable by lazy {
        // Support inflation of vector images before API level 21.
        AppCompatResources.getDrawable(
            app,
            if (amount >= 0) R.drawable.ic_add_24dp
            else R.drawable.ic_remove_24dp)!!
    }

    val status: String  by lazy {
        val confirmations = get("conf")!!.toInt()
        when {
            confirmations <= 0 -> app.getString(R.string.Unconfirmed)
            else -> app.resources.getQuantityString(R.plurals.conf_confirmation,
                                                    confirmations, confirmations)
        }
    }

    override val dialogArguments by lazy {
        Bundle().apply { putString("txid", txid) }
    }
}


class TransactionDialog : DetailDialog() {
    private var _binding: TransactionDetailBinding? = null
    private val binding get() = _binding!!

    val txid by lazy { arguments!!.getString("txid")!! }
    val tx by lazy {
        // Transaction lookup sometimes fails during sync.
        wallet.get("transactions")!!.callAttr("get", txid)
            ?: throw ToastException(R.string.Transaction_not)
    }
    val txInfo by lazy { wallet.callAttr("get_tx_info", tx)!! }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        _binding = TransactionDetailBinding.inflate(LayoutInflater.from(context))
        builder.setView(binding.root)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, {_, _ ->
                setDescription(wallet, txid, binding.etDescription.text.toString())
            })
    }

    override fun onShowDialog() {
        binding.btnExplore.setOnClickListener { exploreTransaction(activity!!, txid) }
        binding.btnCopy.setOnClickListener { copyToClipboard(txid, R.string.transaction_id) }

        binding.tvTxid.text = txid

        // For outgoing transactions, the list view includes the fee in the amount, but the
        // detail view does not.
        binding.tvAmount.text = ltr(formatSatoshisAndUnit(txInfo.get("amount")?.toLong(), signed=true))
        binding.tvTimestamp.text = ltr(formatTime(txInfo.get("timestamp")?.toLong()))
        binding.tvStatus.text = txInfo.get("status")!!.toString()

        val size = tx.callAttr("estimated_size").toInt()
        binding.tvSize.text = getString(R.string.bytes, size)

        val fee = txInfo.get("fee")?.toLong()
        if (fee == null) {
            binding.tvFee.text = getString(R.string.Unknown)
        } else {
            val feeSpb = (fee.toDouble() / size.toDouble()).roundToInt()
            binding.tvFee.text = String.format("%s (%s)",
                                       getString(R.string.sats_per, feeSpb),
                                       ltr(formatSatoshisAndUnit(fee)))
        }
    }

    override fun onFirstShowDialog() {
        binding.etDescription.setText(txInfo.get("label")!!.toString())
    }
}