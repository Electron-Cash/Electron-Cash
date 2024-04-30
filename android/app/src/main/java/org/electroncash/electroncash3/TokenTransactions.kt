package org.electroncash.electroncash3

import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.content.res.AppCompatResources
import com.chaquo.python.PyObject
import org.electroncash.electroncash3.databinding.TokenTransactionsBinding

val guiTokenTransactions by lazy { guiMod("token_transactions") }

class TokenTransactionsFragment : ListFragment(R.layout.token_transactions, R.id.rvTokenTransactions) {
    private var _binding: TokenTransactionsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = TokenTransactionsBinding.inflate(LayoutInflater.from(context))
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
            data.function = { guiTokenTransactions.callAttr("get_token_transactions", wallet) }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnRequest.setOnClickListener { showDialog(this, NewRequestDialog()) }
    }

    override fun onCreateAdapter() = TokenTransactionsAdapter(this)
}


fun TokenTransactionsAdapter(listFragment: ListFragment) =
    ListAdapter(listFragment, R.layout.token_transaction_list, ::TokenTransactionModel,
                ::TransactionDialog)
        .apply { reversed = true }


class TokenTransactionModel(wallet: PyObject, val txHistory: PyObject) : ListItemModel(wallet) {
    private fun get(key: String) = txHistory.get(key)

    val txid by lazy { get("tx_hash")!!.toString() }
    val amount by lazy { get("amount")?.toLong() ?: 0 }
    val balance by lazy { get("balance")?.toLong() ?: 0 }
    val timestamp by lazy { formatTime(get("timestamp")?.toLong()) }
    val label by lazy { getDescription(wallet, txid) }
    val tokenname by lazy { get("token_name")!!.toString() }
    val ftamount by lazy { get("ft_amount_str")!!.toString() }
    val nftamount by lazy { get("nft_amount_str")!!.toString() }
    val ftbalance by lazy { get("ft_balance")!!.toString() }
    val nftbalance by lazy { get("nft_balance")!!.toString() }

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
