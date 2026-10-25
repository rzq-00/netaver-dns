package com.netaver.dns.ui

import android.app.AlertDialog
import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.DnsVpnService
import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs
import com.netaver.dns.util.ProviderCatalog

/**
 * Upstream tab: mode + protocol selectors, the ACTIVE upstream list shown by
 * provider name (resolved via ProviderCatalog), and a catalog of well-known
 * providers to add from. Replaces the old upstream card on Home.
 */
class UpstreamFragment : Fragment() {
    private lateinit var root: LinearLayout
    private lateinit var statusTv: TextView
    private val pingViews = HashMap<String, TextView>()
    private val handler = Handler(Looper.getMainLooper())
    private var ticker: Runnable? = null
    private var building = false

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_upstream, container, false)
        root = v.findViewById(R.id.up_root)
        (activity!!.application as NetAverApp).prefs().migrateUpstreamsIfNeeded()
        rebuild()
        ticker = Runnable {
            refreshStatus()
            handler.postDelayed(ticker!!, 2000)
        }
        return v
    }

    override fun onResume() {
        super.onResume()
        rebuild()
        ticker?.let { handler.post(it) }
    }

    override fun onPause() {
        super.onPause()
        ticker?.let { handler.removeCallbacks(it) }
    }

    private fun prefs(): Prefs = (activity!!.application as NetAverApp).prefs()

    /** After an upstream-config change: restart the VPN (off→on) so it takes
     *  effect when the VPN is running; a no-op while the VPN is off. */
    private fun applyChange() {
        val a = activity as? MainActivity ?: return
        if (a.isVpnRunning()) a.restartVpn()
    }

    // ---------- building blocks ----------

    private fun card(): LinearLayout {
        val c = LinearLayout(activity)
        c.orientation = LinearLayout.VERTICAL
        c.setBackgroundResource(R.drawable.card_bg)
        c.setPadding(dp(12), dp(12), dp(12), dp(12))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.bottomMargin = dp(12)
        c.layoutParams = lp
        return c
    }

    private fun sectionLabel(text: String) {
        val t = TextView(activity)
        t.text = text
        t.setTextColor(0xFF8B93A7.toInt())
        t.textSize = 11f
        t.setPadding(0, dp(2), 0, dp(6))
        root.addView(t)
    }

    private fun cardLabel(text: String): TextView {
        val t = TextView(activity)
        t.text = text
        t.setTextColor(0xFF8B93A7.toInt())
        t.textSize = 11f
        t.setPadding(0, 0, 0, dp(6))
        return t
    }

    private fun chip(text: String, accent: Boolean): TextView {
        val t = TextView(activity)
        t.text = text
        t.textSize = 10.5f
        t.setTextColor((if (accent) 0xFF60A5FA else 0xFFA9B4C8).toInt())
        t.setBackgroundResource(R.drawable.badge_bg)
        t.setPadding(dp(7), dp(2), dp(7), dp(2))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.marginEnd = dp(6)
        t.layoutParams = lp
        return t
    }

    private fun radio(text: String, checked: Boolean): RadioButton {
        val r = RadioButton(activity)
        r.id = View.generateViewId()
        r.text = text
        r.isChecked = checked
        r.setTextColor(0xFFE8EAF0.toInt())
        r.textSize = 14f
        return r
    }

    // ---------- whole-tab rebuild ----------

    private fun rebuild() {
        val act = activity ?: return
        if (!::root.isInitialized) return
        building = true
        pingViews.clear()
        root.removeAllViews()
        val p = prefs()

        // MODE card
        val modeCard = card()
        modeCard.addView(cardLabel(getString(R.string.mode_label)))
        val modeGroup = RadioGroup(act)
        modeGroup.orientation = RadioGroup.HORIZONTAL
        val rPar = radio(getString(R.string.mode_parallel), p.upstreamMode() == Prefs.MODE_PARALLEL)
        val rFast = radio(getString(R.string.mode_fastest), p.upstreamMode() == Prefs.MODE_FASTEST)
        val rSeq = radio(getString(R.string.mode_sequential), p.upstreamMode() == Prefs.MODE_SEQUENTIAL)
        modeGroup.addView(rPar); modeGroup.addView(rFast); modeGroup.addView(rSeq)
        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (building) return@setOnCheckedChangeListener
            val m = when (checkedId) {
                rFast.id -> Prefs.MODE_FASTEST
                rSeq.id -> Prefs.MODE_SEQUENTIAL
                else -> Prefs.MODE_PARALLEL
            }
            prefs().setUpstreamMode(m)
            applyChange()
        }
        modeCard.addView(modeGroup)
        val modeDesc = TextView(act)
        modeDesc.text = getString(R.string.mode_desc)
        modeDesc.setTextColor(0xFF6E7794.toInt())
        modeDesc.textSize = 11f
        modeDesc.setPadding(0, dp(4), 0, 0)
        modeCard.addView(modeDesc)
        root.addView(modeCard)

        // ACTIVE card
        val specs = p.upstreamList()
        val actCard = card()
        actCard.addView(cardLabel(getString(R.string.up_active_fmt, specs.size, Prefs.MAX_UPSTREAMS)))
        if (specs.isEmpty()) {
            val t = TextView(act)
            t.setText(R.string.empty_upstreams)
            t.setTextColor(0xFF8B93A7.toInt())
            t.textSize = 13f
            actCard.addView(t)
        }
        specs.forEachIndexed { idx, spec ->
            actCard.addView(activeRow(idx, spec, specs.size))
        }
        root.addView(actCard)

        // failover status line (moved from Home)
        statusTv = TextView(act)
        statusTv.textSize = 12f
        statusTv.setPadding(dp(2), 0, 0, dp(10))
        root.addView(statusTv)
        refreshStatus()

        // PROTOCOL card (applies to presets and bare IP/hostname entries)
        val protoCard = card()
        protoCard.addView(cardLabel(getString(R.string.upstream_protocol)))
        val protoGroup = RadioGroup(act)
        protoGroup.orientation = RadioGroup.HORIZONTAL
        val rDot = radio("DoT", p.getProtocol() == 1)
        val rDoh = radio("DoH", p.getProtocol() == 2)
        protoGroup.addView(rDot); protoGroup.addView(rDoh)
        protoGroup.setOnCheckedChangeListener { _, checkedId ->
            if (building) return@setOnCheckedChangeListener
            prefs().setProtocol(if (checkedId == rDoh.id) 2 else 1)
            applyChange()
            rebuild()
        }
        protoCard.addView(protoGroup)
        val protoHint = TextView(act)
        protoHint.text = getString(R.string.protocol_hint)
        protoHint.setTextColor(0xFF6E7794.toInt())
        protoHint.textSize = 11f
        protoHint.setPadding(0, dp(4), 0, 0)
        protoCard.addView(protoHint)
        root.addView(protoCard)

        // Catalog
        sectionLabel(getString(R.string.up_add_provider))
        val inList = HashSet<String>()
        for (s in specs) {
            val id = ProviderCatalog.identify(s, p.getProtocol())
            if (id.known) inList.add(id.providerName)
        }
        for ((i, provider) in ProviderCatalog.providers.withIndex()) {
            root.addView(providerCard(i, provider, inList.contains(provider.name)))
        }
        root.addView(customCard())
        building = false
    }

    private fun activeRow(idx: Int, spec: String, count: Int): View {
        val act = activity!!
        val p = prefs()
        val id = ProviderCatalog.identify(spec, p.getProtocol())
        val row = LinearLayout(act)
        row.orientation = LinearLayout.HORIZONTAL
        row.setPadding(0, dp(7), 0, dp(7))

        val num = TextView(act)
        num.text = "${idx + 1}"
        num.setTextColor(0xFF8B93A7.toInt())
        num.textSize = 13f
        num.setPadding(0, dp(2), dp(10), 0)
        row.addView(num)

        val mid = LinearLayout(act)
        mid.orientation = LinearLayout.VERTICAL
        mid.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val nameRow = LinearLayout(act)
        nameRow.orientation = LinearLayout.HORIZONTAL
        val name = TextView(act)
        name.text = if (id.known) id.providerName else getString(R.string.up_custom_name)
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 15f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        nameRow.addView(name)
        val ch = chip(ProviderCatalog.chipText(id), true)
        val chLp = ch.layoutParams as LinearLayout.LayoutParams
        chLp.marginStart = dp(8)
        ch.layoutParams = chLp
        nameRow.addView(ch)
        mid.addView(nameRow)
        val addr = TextView(act)
        addr.text = ProviderCatalog.addressLine(spec)
        addr.setTextColor(0xFF8B93A7.toInt())
        addr.textSize = 11.5f
        addr.typeface = android.graphics.Typeface.MONOSPACE
        mid.addView(addr)
        row.addView(mid)

        // per-provider ping (passive latency EMA published by the service)
        val pingCol = LinearLayout(act)
        pingCol.orientation = LinearLayout.VERTICAL
        pingCol.gravity = android.view.Gravity.END
        pingCol.setPadding(dp(10), dp(2), dp(12), 0)
        val pl = TextView(act)
        pl.setText(R.string.ping_label)
        pl.setTextColor(0xFF6E7794.toInt())
        pl.textSize = 9.5f
        pl.gravity = android.view.Gravity.END
        pingCol.addView(pl)
        val pv = TextView(act)
        pv.text = "—"
        pv.setTextColor(0xFF6E7794.toInt())
        pv.textSize = 13f
        pv.setTypeface(pv.typeface, android.graphics.Typeface.BOLD)
        pv.gravity = android.view.Gravity.END
        pingCol.addView(pv)
        pingViews[spec] = pv
        row.addView(pingCol)

        val del = Button(act)
        del.text = "✕"
        del.setOnClickListener {
            val specs = prefs().upstreamList().toMutableList()
            if (specs.size <= 1) {
                Toast.makeText(act, R.string.min_one_upstream, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (idx in specs.indices) {
                specs.removeAt(idx)
                prefs().setUpstreamList(specs)
                rebuild()
                applyChange()
            }
        }
        row.addView(del)
        if (idx < count - 1) {
            // separators handled by row padding; keep rows visually light
        }
        return row
    }

    private fun providerCard(index: Int, provider: ProviderCatalog.Provider, isInList: Boolean): View {
        val act = activity!!
        val c = card()
        val top = LinearLayout(act)
        top.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(act)
        left.orientation = LinearLayout.VERTICAL
        left.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val name = TextView(act)
        name.text = provider.name
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 16f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        left.addView(name)
        val trait = TextView(act)
        trait.setText(provider.traitRes)
        trait.setTextColor(0xFF8B93A7.toInt())
        trait.textSize = 12.5f
        left.addView(trait)
        top.addView(left)
        if (isInList) {
            val t = TextView(act)
            t.text = getString(R.string.up_in_list)
            t.setTextColor(0xFF8B93A7.toInt())
            t.textSize = 12f
            t.setTypeface(t.typeface, android.graphics.Typeface.BOLD)
            top.addView(t)
        } else {
            val b = Button(act)
            b.setText(R.string.add)
            b.setOnClickListener { (act as MainActivity).openProviderDetail(index) }
            top.addView(b)
        }
        c.addView(top)
        val names = provider.variants.map { it.name }.filter { it.isNotEmpty() }
        if (names.isNotEmpty()) {
            val chips = LinearLayout(act)
            chips.orientation = LinearLayout.HORIZONTAL
            chips.setPadding(0, dp(8), 0, 0)
            for (n in names) chips.addView(chip(n, false))
            c.addView(chips)
        }
        c.setOnClickListener { (act as MainActivity).openProviderDetail(index) }
        return c
    }

    private fun customCard(): View {
        val act = activity!!
        val c = card()
        val top = LinearLayout(act)
        top.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(act)
        left.orientation = LinearLayout.VERTICAL
        left.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val name = TextView(act)
        name.setText(R.string.custom_ellipsis)
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 16f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        left.addView(name)
        val trait = TextView(act)
        trait.setText(R.string.trait_custom)
        trait.setTextColor(0xFF8B93A7.toInt())
        trait.textSize = 12.5f
        left.addView(trait)
        top.addView(left)
        val b = Button(act)
        b.setText(R.string.add)
        b.setOnClickListener { showCustomDialog() }
        top.addView(b)
        c.addView(top)
        c.setOnClickListener { showCustomDialog() }
        return c
    }

    private fun showCustomDialog() {
        val act = activity ?: return
        val et = EditText(act)
        et.hint = "tls://dns.example.com or https://dns.example.com/dns-query"
        et.setSingleLine(true)
        AlertDialog.Builder(act)
            .setTitle(R.string.custom_ellipsis)
            .setView(et)
            .setPositiveButton(R.string.add) { _, _ ->
                val raw = et.text.toString().trim()
                if (!Prefs.parseCustomUpstream(raw).valid) {
                    Toast.makeText(act, R.string.bad_format_upstream, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                val specs = prefs().upstreamList().toMutableList()
                if (specs.size >= Prefs.MAX_UPSTREAMS) {
                    Toast.makeText(act, getString(R.string.max_upstreams_fmt, Prefs.MAX_UPSTREAMS),
                        Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (specs.contains(raw)) {
                    Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                // U5: a different spelling of an already-active server is a dupe too
                val newKey = ProviderCatalog.endpointKey(raw, prefs())
                if (specs.any { ProviderCatalog.endpointKey(it, prefs()) == newKey }) {
                    Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                specs.add(raw)
                prefs().setUpstreamList(specs)
                rebuild()
                applyChange()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun refreshStatus() {
        val act = activity ?: return
        if (!::statusTv.isInitialized) return
        val running = (act as MainActivity).isVpnRunning()
        val st = if (running) DnsVpnService.upstreamStatusLine else ""
        statusTv.text = st
        val down = st.contains("DOWN")
        statusTv.setTextColor((if (down) 0xFFFBBF24 else 0xFF8B93A7).toInt())
        // per-provider ping values (green when the VPN is up and the upstream
        // has answered real queries; em dash otherwise)
        for ((spec, tv) in pingViews) {
            val ms = if (running) DnsVpnService.upstreamPingMs[spec] else null
            if (ms != null) {
                tv.text = "$ms ms"
                tv.setTextColor(0xFF4ADE80.toInt())
            } else {
                tv.text = "—"
                tv.setTextColor(0xFF6E7794.toInt())
            }
        }
    }
}
