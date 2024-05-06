package org.electroncash.electroncash3

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.Kwarg
import com.chaquo.python.PyObject
import com.google.zxing.integration.android.IntentIntegrator
import org.electroncash.electroncash3.databinding.ContactDetailBinding
import org.electroncash.electroncash3.databinding.ContactsBinding

val guiContacts by lazy { guiMod("contacts") }
val libContacts by lazy { libMod("contacts") }


class ContactsFragment : ListFragment(R.layout.contacts, R.id.rvContacts) {
    private var _binding: ContactsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = ContactsBinding.inflate(LayoutInflater.from(context))
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(daemonUpdate)
            trigger.addSource(settings.getBoolean("cashaddr_format"))
            data.function = { guiContacts.callAttr("get_contacts", wallet)!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnAdd.setOnClickListener { showDialog(this, ContactDialog()) }
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.contact_list, ::ContactModel, ::ContactDialog)
}


class ContactModel(wallet: PyObject, val contact: PyObject) : ListItemModel(wallet) {
    val name by lazy {
        contact.get("name").toString()
    }
    val addr by lazy {
        makeAddress(contact.get("address").toString())
    }
    val addrString by lazy {
        val addrFormat = if (contact.get("type").toString() == "tokenaddr") {
            "to_token_string"
        } else {
            "to_ui_string"
        }
        addr.callAttr(addrFormat).toString()
    }
    override val dialogArguments by lazy {
        Bundle().apply {
            putString("name", name)
            putString("address", addrString)
        }
    }
}


class ContactDialog : DetailDialog() {
    private var _binding: ContactDetailBinding? = null
    private val binding get() = _binding!!

    val existingContact by lazy {
        if (arguments == null) null
        else ContactModel(wallet, makeContact(arguments!!.getString("name")!!,
                                              arguments!!.getString("address")!!))
    }

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        _binding = ContactDetailBinding.inflate(LayoutInflater.from(context))
        with (builder) {
            setView(binding.root)
            setNegativeButton(android.R.string.cancel, null)
            setPositiveButton(android.R.string.ok, null)
            setNeutralButton(if (existingContact == null) R.string.scan_qr
                             else R.string.delete,
                             null)
        }
    }

    override fun onShowDialog() {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { onOK() }

        val contact = existingContact
        if (contact == null) {
            for (btn in listOf(binding.btnExplore, binding.btnSend)) {
                (btn as View).visibility = View.INVISIBLE
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { scanQR(this) }
        } else {
            binding.btnExplore.setOnClickListener {
                exploreAddress(activity!!, contact.addr)
            }
            binding.btnSend.setOnClickListener {
                try {
                    showDialog(activity!!, SendDialog().apply {
                        arguments = Bundle().apply {
                            putString("address", contact.addrString)
                        }
                    })
                    dismiss()
                } catch (e: ToastException) { e.show() }
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                showDialog(this, ContactDeleteDialog().apply {
                    arguments = contact.dialogArguments
                })
            }
        }
    }

    override fun onFirstShowDialog() {
        val contact = existingContact
        if (contact != null) {
            binding.etName.setText(contact.name)
            binding.etAddress.setText(contact.addrString)
        } else {
            binding.etName.requestFocus()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            binding.etAddress.setText(result.contents)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    fun onOK() {
        val name = binding.etName.text.toString()
        val address = binding.etAddress.text.toString()
        try {
            if (name.isEmpty()) {
                throw ToastException(R.string.name_is, Toast.LENGTH_SHORT)
            }
            makeAddress(address)  // Throws ToastException if invalid.
            val contacts = wallet.get("contacts")!!
            contacts.callAttr("add", makeContact(name, address), existingContact?.contact,
                               Kwarg("save", false))
            saveContacts(wallet, contacts)
            dismiss()
        } catch (e: ToastException) { e.show() }
    }
}


class ContactDeleteDialog : AlertDialogFragment() {
    override fun onBuildDialog(builder: AlertDialog.Builder) {
        val contactDialog = targetFragment as ContactDialog
        val wallet = contactDialog.wallet
        builder.setTitle(R.string.confirm_delete)
            .setMessage(R.string.are_you_sure_you_wish_to_delete)
            .setPositiveButton(R.string.delete) { _, _ ->
                val contacts = wallet.get("contacts")!!
                contacts.callAttr("remove", makeContact(arguments!!.getString("name")!!,
                                                        arguments!!.getString("address")!!),
                                  Kwarg("save", false))
                saveContacts(wallet, contacts)
                contactDialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
    }
}


fun makeContact(name: String, addr: String): PyObject {
    val addressType = if (isTokenAddress(addr)) "tokenaddr" else "address"
    return libContacts.callAttr(
        "Contact", name, makeAddress(addr).callAttr("to_storage_string"),
        addressType
    )!!
}


fun saveContacts(wallet: PyObject, contacts: PyObject) {
    saveWallet(wallet) { contacts.callAttr("save") }
    daemonUpdate.setValue(Unit)
}