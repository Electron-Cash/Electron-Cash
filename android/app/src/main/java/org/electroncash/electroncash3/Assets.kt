package org.electroncash.electroncash3

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.fragment.app.replace


class AssetsFragment : Fragment(R.layout.assets), MainFragment {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val spinner: Spinner = view.findViewById(R.id.spnAssetType)
        ArrayAdapter.createFromResource(
            activity!!,
            R.array.asset_type,
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
                    0 -> replaceAssetsFragment<AddressesFragment>()
                    1 -> replaceAssetsFragment<TokensFragment>()
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>) { }
        }
    }

    private inline fun <reified T: Fragment> replaceAssetsFragment() {
        requireActivity().supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace<T>(R.id.assets_container)
        }
    }
}
