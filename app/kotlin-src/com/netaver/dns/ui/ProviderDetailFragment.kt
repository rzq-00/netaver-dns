package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs
import com.netaver.dns.util.ProviderCatalog

/** Provider detail: pick a protocol + variant, then add it as an upstream. */
class ProviderDetailFragment : Fragment() {
    private lateinit var rootBox: LinearLayout
    private var providerIdx = 0
    private var variantIdx = 0
    private var proto = ProviderCatalog.PROTO_DOT

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        providerIdx = arguments?.getInt(ARG_INDEX, 0) ?: 0
        val v = inflater.inflate(R.layout.fragment_provider, container, false)
        val provider = ProviderCatalog.providers[providerIdx]
        v.findViewById<TextView>(R.id.prov_name).text = provider.name
        v.findViewById<TextView>(R.id.prov_trait).setText(provider.traitRes)
        rootBox = v.findViewById(R.id.prov_root)
        variantIdx = 0
        proto = provider.variants[0].protocols().firstOrNull() ?: ProviderCatalog.PROTO_DOT
        // U-N4: rotation must not silently reset the picked variant/protocol
        if (savedInstanceState != null) {
            val vi = savedInstanceState.getInt(STATE_VARIANT, 0)
            if (vi in provider.variants.indices) variantIdx = vi
            val pr = savedInstanceState.getInt(STATE_PROTO, proto)
            if (provider.variants[variantIdx].protocols().contains(pr)) proto = pr
        }
        rebuild()
        return v
    }

    // U-N4: persist variant/protocol across rotation (see onCreateView)
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(STATE_VARIANT, variantIdx)
        outState.putInt(STATE_PROTO, proto)
    }

    private fun prefs(): Prefs = (activity!!.application as NetAverApp).prefs()

    private fun rebuild() {
        val act = activity ?: return
        if (!::rootBox.isInitialized) return
        val provider = ProviderCatalog.providers[providerIdx]
        val variant = provider.variants[variantIdx]
        rootBox.removeAllViews()

        // protocol selector (only the transports this variant offers)
        val protoLabel = TextView(act)
        protoLabel.setText(R.string.up_protocol)
        protoLabel.setTextColor(0xFF8B93A7.toInt())
        protoLabel.textSize = 11f
        protoLabel.setPadding(0, 0, 0, dp(6))
        rootBox.addView(protoLabel)
        val protoRow = LinearLayout(act)
        protoRow.orientation = LinearLayout.HORIZONTAL
        for (pr in variant.protocols()) {
            val b = Button(act)
            b.text = when (pr) {
                ProviderCatalog.PROTO_DOH -> getString(R.string.up_proto_doh)
                ProviderCatalog.PROTO_IPV4 -> getString(R.string.up_proto_ipv4)
                else -> getString(R.string.up_proto_dot)
            }
            if (pr == proto) {
                b.setTextColor(0xFF60A5FA.toInt())
                b.setTypeface(b.typeface, android.graphics.Typeface.BOLD)
            }
            b.setOnClickListener { proto = pr; rebuild() }
            protoRow.addView(b)
        }
        rootBox.addView(protoRow)

        // variant selector (skipped for single-flavor providers)
        if (provider.variants.size > 1) {
            val varLabel = TextView(act)
            varLabel.setText(R.string.up_variant)
            varLabel.setTextColor(0xFF8B93A7.toInt())
            varLabel.textSize = 11f
            varLabel.setPadding(0, dp(14), 0, dp(6))
            rootBox.addView(varLabel)
            provider.variants.forEachIndexed { i, vr ->
                rootBox.addView(variantRow(provider, i, vr))
            }
        } else {
            val addr = TextView(act)
            addr.text = variant.specFor(proto)
            addr.setTextColor(0xFFA9B4C8.toInt())
            addr.textSize = 13f
            addr.typeface = android.graphics.Typeface.MONOSPACE
            addr.setPadding(0, dp(14), 0, 0)
            rootBox.addView(addr)
        }

        val use = Button(act)
        use.setText(R.string.up_use_upstream)
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.topMargin = dp(18)
        use.layoutParams = lp
        use.setOnClickListener { addChosen() }
        rootBox.addView(use)
    }

    private fun variantRow(
        provider: ProviderCatalog.Provider,
        i: Int,
        vr: ProviderCatalog.Variant
    ): View {
        val act = activity!!
        val row = LinearLayout(act)
        row.orientation = LinearLayout.HORIZONTAL
        row.setBackgroundResource(R.drawable.card_bg)
        row.setPadding(dp(12), dp(10), dp(12), dp(10))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.bottomMargin = dp(8)
        row.layoutParams = lp

        val rb = RadioButton(act)
        rb.isChecked = i == variantIdx
        rb.isClickable = false
        row.addView(rb)

        val mid = LinearLayout(act)
        mid.orientation = LinearLayout.VERTICAL
        val name = TextView(act)
        name.text = vr.name
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 15f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        mid.addView(name)
        val addr = TextView(act)
        // address preview for the currently selected protocol; fall back to
        // the variant's first offered protocol when it lacks the selected one
        val pr = if (vr.protocols().contains(proto)) proto else vr.protocols().first()
        addr.text = vr.specFor(pr)
        addr.setTextColor(0xFF8B93A7.toInt())
        addr.textSize = 12f
        addr.typeface = android.graphics.Typeface.MONOSPACE
        mid.addView(addr)
        row.addView(mid)

        row.setOnClickListener {
            variantIdx = i
            val vrNow = provider.variants[variantIdx]
            if (!vrNow.protocols().contains(proto)) {
                proto = vrNow.protocols().first()
            }
            rebuild()
        }
        return row
    }

    private fun addChosen() {
        val act = activity ?: return
        val provider = ProviderCatalog.providers[providerIdx]
        val variant = provider.variants[variantIdx]
        val pr = if (variant.protocols().contains(proto)) proto else variant.protocols().first()
        val spec = variant.specFor(pr)
        val specs = prefs().upstreamList().toMutableList()
        if (specs.size >= Prefs.MAX_UPSTREAMS) {
            Toast.makeText(act, getString(R.string.max_upstreams_fmt, Prefs.MAX_UPSTREAMS),
                Toast.LENGTH_SHORT).show()
            return
        }
        if (specs.contains(spec)) {
            Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
            return
        }
        // U5: a different spelling of an already-active server is a dupe too
        val newKey = ProviderCatalog.endpointKey(spec, prefs())
        if (specs.any { ProviderCatalog.endpointKey(it, prefs()) == newKey }) {
            Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
            return
        }
        specs.add(spec)
        prefs().setUpstreamList(specs)
        Toast.makeText(act, R.string.up_added, Toast.LENGTH_SHORT).show()
        // restart the VPN (off→on) so the new upstream takes effect when running
        val ma = act as? MainActivity
        if (ma != null && ma.isVpnRunning()) ma.restartVpn()
        act.fragmentManager.popBackStack()
    }

    companion object {
        private const val ARG_INDEX = "provider_index"
        private const val STATE_VARIANT = "state_variant"
        private const val STATE_PROTO = "state_proto"
        fun newInstance(index: Int): ProviderDetailFragment {
            val f = ProviderDetailFragment()
            val b = Bundle()
            b.putInt(ARG_INDEX, index)
            f.arguments = b
            return f
        }
    }
}
