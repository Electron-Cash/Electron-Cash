package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import com.chaquo.python.PyObject
import org.electroncash.electroncash3.databinding.FusionBinding
import org.electroncash.electroncash3.databinding.FusionSettingsBinding


val fusion = daemonModel.daemon.get("plugins")!!.callAttr("find_plugin", "fusion")
val wallet = daemonModel.wallet

val FUSIONTYPES = HashMap<Int, String>() .apply {
    put(0, "normal")
    put(1, "fan-out")
    put(2, "consolidate")
}


class FusionFragment : ListFragment(R.layout.fusion, R.id.rvFusion)  {
    private var _binding: FusionBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        _binding = FusionBinding.inflate(LayoutInflater.from(context))
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onListModelCreated(listModel: ListModel) {
        with (listModel) {
            trigger.addSource(fusionUpdate)
            data.function = { fusion.callAttr("get_all_fusions")!! }

        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnFusionSettings.setOnClickListener { showDialog(this, FusionSettingsDialog()) }
        binding.btnActivateFusion.setOnClickListener { toggleFusion() }

        if (fusion.callAttr("is_autofusing", wallet).toBoolean()){
            binding.btnActivateFusion.setImageResource(R.drawable.ic_pause_circle_24dp)
        } else {
            binding.btnActivateFusion.setImageResource(R.drawable.ic_not_started_24dp)
        }
    }

    override fun onCreateAdapter() =
        ListAdapter(this, R.layout.fusion_list, ::FusionModel, ::FusionSettingsDialog)

    fun toggleFusion() {
        val is_autofusing = fusion.callAttr("is_autofusing", this.wallet).toBoolean()
        if (is_autofusing) {
            fusion.callAttr("disable_autofusing", this.wallet)
            binding.btnActivateFusion.setImageResource(R.drawable.ic_not_started_24dp)
        } else {
            showDialog(this, FusionPasswordDialog())
            if (!fusion.callAttr("is_autofusing", this.wallet).toBoolean()){
                binding.btnActivateFusion.setImageResource(R.drawable.ic_pause_circle_24dp)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        warnIfTorUnvailable()
    }

    fun warnIfTorUnvailable() {
        val torAvailable = fusion.callAttr("scan_torport")
        if (torAvailable == null) {
            binding.tvFusion.visibility = View.VISIBLE
            binding.tvFusion.text = getString(R.string.tor_not)
        } else {
            binding.tvFusion.visibility = View.GONE
        }
    }
}

class FusionPasswordDialog: PasswordDialog<Unit>() {
    override fun onPassword(password: String) {
        fusion.callAttr("enable_autofusing", wallet, password)
    }
}


class FusionModel(wallet: PyObject, val fusionObject: PyObject) : ListItemModel(wallet) {
    val status by lazy {
        fusionObject.get("status")!!.asList().get(0).toString()
    }
    val statusExtra by lazy {
        fusionObject.get("status")!!.asList().get(1).toString()
    }

    override val dialogArguments by lazy {
        Bundle().apply {
            putString("status", status)
            putString("statusExtra", statusExtra)
        }
    }
}



class FusionSettingsDialog: DetailDialog() {
    private var _binding: FusionSettingsBinding? = null
    private val binding get() = _binding!!

    override fun onBuildDialog(builder: AlertDialog.Builder) {
        _binding = FusionSettingsBinding.inflate(LayoutInflater.from(context))
        builder.setTitle(R.string.fusion_settings)
            .setView(binding.root)
            .setPositiveButton(R.string.save, null)
            .setNegativeButton(R.string.cancel, null)
    }

    override fun onShowDialog() {
        super.onShowDialog()

        val walletConf = fusion.callAttr("get_wallet_conf", this.wallet)
        val serverInfo = fusion.callAttr("get_server").asList()
        val serverURL = serverInfo[0].toString()
        val serverPort = serverInfo[1].toString()
        val serverUseSSL = serverInfo[2].toBoolean()

        val fusionTypes: MutableList<String> = ArrayList()
        fusionTypes.add(getString(R.string.normal))
        fusionTypes.add(getString(R.string.Fan_out))
        fusionTypes.add(getString(R.string.consolidate))
        binding.spFusionType.adapter = SimpleArrayAdapter(context!!, fusionTypes)

        binding.tvFusionUrl.setText(serverURL)
        binding.tvFusionPort.setText(serverPort)
        binding.swFusionUseSSL.isChecked = serverUseSSL

        val fusionMode = walletConf.get("fusion_mode").toString()
        for ((key, value) in FUSIONTYPES){
            if (fusionMode == value) {
                binding.spFusionType.setSelection(key)
            }
        }

        val fusionDepths: MutableList<String> = (0..10).map { it.toString() }.toMutableList()
        fusionDepths[0] = getString(R.string.fuse_forever)
        binding.spFusionDepth.adapter = SimpleArrayAdapter(context!!, fusionDepths)

        val fusionDepth = walletConf.get("fuse_depth")!!.toInt()
        binding.spFusionDepth.setSelection(fusionDepth)


        val spendOnlyFusedCoins = walletConf.get("spend_only_fused_coins")!!.toBoolean()
        binding.swFusionSpendOnlyFusedCoins.isChecked = spendOnlyFusedCoins



        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener{ saveSettings() }
    }

    fun saveSettings() {

        val serverUrl = binding.tvFusionUrl.text.toString()
        val serverPort = binding.tvFusionPort.text.toString().toInt()
        val serverUseSSL = binding.swFusionUseSSL.isChecked
        val selectedFusionTypePosition = binding.spFusionType.selectedItemPosition
        val selectedFusionDepthPosition = binding.spFusionDepth.selectedItemPosition
        val spendOnlyFusedCoins = binding.swFusionSpendOnlyFusedCoins.isChecked

        val walletConf = fusion.callAttr("get_wallet_conf", this.wallet)

        fusion.callAttr("set_server", serverUrl, serverPort, serverUseSSL)
        walletConf.put("fusion_mode", PyObject.fromJava(FUSIONTYPES.get(selectedFusionTypePosition)))
        walletConf.put("fuse_depth", selectedFusionDepthPosition)
        walletConf.put("spend_only_fused_coins", spendOnlyFusedCoins)


        dismiss()
    }
}