package org.electroncash.electroncash3

import android.content.Context
import android.os.Bundle
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.widget.Button
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.replace
import androidx.fragment.app.commit
import androidx.fragment.app.viewModels
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel

class TransactionsFragment : Fragment(R.layout.transactions) {
    class Model : ViewModel() {
        val filter = MutableLiveData<Int>().apply {
            value = R.id.bchTransactions
        }
    }
    val model: Model by viewModels()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val btn = view!!.findViewById<Button>(R.id.btnTxType)
        btn.setOnClickListener {
            showDialog(this, TxTypeDialog().apply { arguments = Bundle().apply {
                putInt("labelId", R.string.transaction_type)
                putInt("menuId", R.menu.transaction_type)
            }})
        }

        val liveData = model.filter
        val menu = inflateMenu(R.menu.transaction_type)
        liveData.observe(viewLifecycleOwner, Observer {
            btn.setText("${menu.findItem(liveData.value!!).title}")
            refreshTxFragment()
        })
    }

    fun refreshTxFragment() {
        switchTxFragment(model.filter.value!!)
    }

    private fun switchTxFragment(txId: Int) {
        when (txId) {
            R.id.bchTransactions -> replaceTxFragment<BchTransactionsFragment>()
            R.id.tokenTransactions -> replaceTxFragment<TokenTransactionsFragment>()
            R.id.fusionTransactions -> replaceTxFragment<FusionFragment>()
        }
    }

    private inline fun <reified T: Fragment> replaceTxFragment() {
        requireActivity().supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace<T>(R.id.fragment_container_view)
        }
    }
}

class TxTypeDialog : MenuDialog() {

    val menuId by lazy { arguments!!.getInt("menuId") }
    val liveData by lazy {
        (targetFragment as TransactionsFragment).model.filter
    }

    override fun onBuildDialog(builder: AlertDialog.Builder, menu: Menu) {
        builder.setTitle(arguments!!.getInt("labelId"))
        MenuInflater(app).inflate(menuId, menu)
        menu.findItem(liveData.value!!).isChecked = true
    }

    override fun onMenuItemSelected(item: MenuItem) {
        liveData.value = item.itemId
        dismiss()
    }
}