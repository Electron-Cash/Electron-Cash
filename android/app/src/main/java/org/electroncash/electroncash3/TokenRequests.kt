package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.chaquo.python.Kwarg
import org.electroncash.electroncash3.databinding.TokenRequestsBinding


class TokenRequestsFragment : ListFragment(R.layout.token_requests, R.id.rvTokenRequests) {
    private var _binding: TokenRequestsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = TokenRequestsBinding.inflate(inflater, container, false)
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
            data.function = { wallet.callAttr("get_sorted_requests", daemonModel.config,
                                              Kwarg("filter_asset", "token"))!! }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnAdd.setOnClickListener {
            showDialog(this, NewRequestDialog().apply { arguments = Bundle().apply {
                putBoolean("token_request", true)
            }})
        }
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.token_request_list, ::RequestModel, ::RequestDialog)
}
