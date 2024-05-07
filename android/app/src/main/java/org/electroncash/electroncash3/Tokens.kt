package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.PyObject
import org.electroncash.electroncash3.databinding.TokensBinding


import android.app.Dialog
import android.widget.EditText

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.fragment.app.DialogFragment



val guiTokens by lazy { guiMod("tokens") }

// Not fully implemented yet.
class TokenMint : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return activity?.let { activity ->
            val builder = AlertDialog.Builder(activity)
            builder.setTitle("Mint New Token")
                    .setPositiveButton(android.R.string.ok, null)
                    .setNegativeButton(android.R.string.cancel, null)
            builder.create()
        } ?: throw IllegalStateException("Activity cannot be null")
    }
}


// This class deals with the main UI display for the screen, displaying each category as a row
class TokensFragment : ListFragment(R.layout.tokens, R.id.rvTokens) {
    private var _binding: TokensBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = TokensBinding.inflate(LayoutInflater.from(context))
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
            data.function = { guiTokens.callAttr("get_tokens", wallet)!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnAdd.setOnClickListener { showDialog(this, TokenMint()) }
    }

    override fun onCreateAdapter() =
            ListAdapter(this, R.layout.token_list, ::TokenModel, ::TokenDialog)



}

// The model for dealing with the tokens, each row needs the name, amount, nft, and id.
class TokenModel(wallet: PyObject, tokenPy: PyObject) : ListItemModel(wallet) {
    private val tokenMap: Map<String, String> = tokenPy.asMap().mapKeys { it.key.toString() }.mapValues { it.value.toString() }

    val tokenName: String by tokenMap
    val amount: String by tokenMap
    val nft: String by tokenMap
    val tokenId: String by tokenMap

    override val dialogArguments: Bundle by lazy {
        Bundle().apply {
            putString("tokenName", tokenName)
            putString("amount", amount)
            putString("nft", nft)
            putString("tokenId", tokenId)
        }
    }
}


// This class deals with the dialog window that appears when you tap a token row.
class TokenDialog : DetailDialog() {
    private var tokenId: String = "default_token_id"

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        tokenId = arguments?.getString("tokenId", "default_token_id") ?: "default_token_id"
        val displayTokenId = tokenId.take(10) + "..." + tokenId.takeLast(10)
        builder.setTitle("Token Category $displayTokenId")
               .setItems(arrayOf("Category Properties", "Copy Category ID")) { _, which ->
                   when (which) {
                       0 -> showCategoryProperties()
                       1 -> copyCategoryIdToClipboard()
                   }
               }
               .setNegativeButton(android.R.string.cancel, null)
    }

    // When modifying a category, call to open another dialog
    private fun showCategoryProperties() {
        val dialog = CategoryPropertiesDialog()
        dialog.arguments = Bundle().apply {
            putString("token_id", tokenId)
        }
        dialog.show(requireActivity().supportFragmentManager, "categoryProperties")
    }

    // Copy to clipboard
    private fun copyCategoryIdToClipboard() {
        val clipboard = context?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Category ID", tokenId)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(context, "Token ID copied to clipboard", Toast.LENGTH_SHORT).show()
    }
}


// This class deals with the dialog window for modifying the token properties such as token  name.
class CategoryPropertiesDialog : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return activity?.let { activity ->
            val builder = AlertDialog.Builder(activity)
            val inflater = activity.layoutInflater
            val view = inflater.inflate(R.layout.token_category_properties, null)
            val editTextCategoryName = view.findViewById<EditText>(R.id.editTextCategoryName)
            val editTextCategoryDecimals = view.findViewById<EditText>(R.id.editTextCategoryDecimals)

            // Retrieve the token ID passed as an argument
            val tokenId = arguments?.getString("token_id") ?: "default_token_id"
            // Get the existing details from the backend
            val existingTokenName = guiTokens.callAttr("get_token_name", tokenId).toString()
            val existingTokenDecimals = guiTokens.callAttr("get_token_decimals", tokenId).toString()
            // Set the existing details in the EditText
            editTextCategoryName.setText(existingTokenName)
            // Leave the field blank if decimals is zero
            val tokenDecimals = if (existingTokenDecimals == "0") "" else existingTokenDecimals
            editTextCategoryDecimals.setText(tokenDecimals)

            builder.setView(view)
            builder.setTitle("Category Properties")
            .setPositiveButton("Save") { dialog, id ->
                val inputName = editTextCategoryName.text.toString()
                val inputDecimals = editTextCategoryDecimals.text.toString()
                var decimals = if (inputDecimals == "") {
                    0
                } else {
                    try {
                        inputDecimals.toShort()
                    } catch (e: NumberFormatException) {
                        toast(R.string.Invalid_amount)
                        0
                    }
                }
                if (decimals > 18) {
                    toast(R.string.token_decimals_cannot)
                    decimals = 18
                }
                // Save the data
                saveTokenData(tokenId, inputName, decimals)
            }
            .setNegativeButton(android.R.string.cancel, null)
            builder.create()
        } ?: throw IllegalStateException("Activity cannot be null")
    }

    // Call the Python backend to save the updated token details.
    private fun saveTokenData(tokenId: String, displayName: String, decimals: Short) {
        guiTokens.callAttr("save_token_data", tokenId, displayName, decimals)
        daemonUpdate.setValue(Unit)  // Needed so the screen refreshes with the updated changes.
    }
}

