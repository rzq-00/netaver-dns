package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.DnsVpnService
import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs

/** Home tab: power button, stats, upstream provider + protocol selector. */
class HomeFragment : Fragment() {
    private lateinit var statusTv: TextView
    private lateinit var powerLabel: TextView
    private lateinit var uptimeTv: TextView
    private lateinit var latencyTv: TextView
    private lateinit var statQueries: TextView
    private lateinit var statBlocked: TextView
    private lateinit var statRate: TextView
    private lateinit var statUpstream: TextView
    private lateinit var statLatency: TextView
    private lateinit var powerBtn: ImageButton
    private lateinit var checkSpinner: ProgressBar
    private lateinit var modeGroup: RadioGroup
    private lateinit var protocolGroup: RadioGroup
    private lateinit var upstreamListBox: LinearLayout
    private lateinit var addPresetGroup: RadioGroup
    private lateinit var addCustomBox: View
    private lateinit var addCustomEt: EditText
    private lateinit var addBtn: Button
    private lateinit var upstreamStatusTv: TextView
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var ticker: Runnable
    private var updatingRadio = false
    private var checking = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_home, container, false)
        statusTv = v.findViewById(R.id.home_status)
        powerLabel = v.findViewById(R.id.power_label)
        uptimeTv = v.findViewById(R.id.uptime_label)
        statQueries = v.findViewById(R.id.stat_queries)
        statBlocked = v.findViewById(R.id.stat_blocked)
        statRate = v.findViewById(R.id.stat_rate)
        statUpstream = v.findViewById(R.id.stat_upstream)
        statLatency = v.findViewById(R.id.stat_latency)
        powerBtn = v.findViewById(R.id.power_button)
        latencyTv = v.findViewById(R.id.latency_live)
        checkSpinner = v.findViewById(R.id.check_spinner)
        modeGroup = v.findViewById(R.id.mode_group)
        protocolGroup = v.findViewById(R.id.protocol_group)
        upstreamListBox = v.findViewById(R.id.upstream_list_box)
        addPresetGroup = v.findViewById(R.id.add_preset_group)
        addCustomBox = v.findViewById(R.id.add_custom_box)
        addCustomEt = v.findViewById(R.id.add_custom_text)
        addBtn = v.findViewById(R.id.add_upstream_btn)
        upstreamStatusTv = v.findViewById(R.id.upstream_status)

        powerBtn.setOnClickListener { (activity as MainActivity).toggleVpn() }

        val app0 = activity!!.application as NetAverApp
        app0.prefs().migrateUpstreamsIfNeeded()

        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (updatingRadio) return@setOnCheckedChangeListener
            val app = activity!!.application as NetAverApp
            val m = if (checkedId == R.id.mode_fastest) Prefs.MODE_FASTEST
                else if (checkedId == R.id.mode_sequential) Prefs.MODE_SEQUENTIAL
                else Prefs.MODE_PARALLEL
            app.prefs().setUpstreamMode(m)
            refreshUpstreamLabel()
        }

        addPresetGroup.setOnCheckedChangeListener { _, checkedId ->
            addCustomBox.visibility =
                if (checkedId == R.id.add_custom) View.VISIBLE else View.GONE
        }

        addBtn.setOnClickListener { addUpstreamFromForm() }

        protocolGroup.setOnCheckedChangeListener { _, checkedId ->
            if (updatingRadio) return@setOnCheckedChangeListener
            val app = activity!!.application as NetAverApp
            val proto = if (checkedId == R.id.proto_doh) 2 else 1 // DoT / DoH only
            app.prefs().setProtocol(proto)
            refreshUpstreamLabel()
        }

        ticker = Runnable {
            refresh()
            handler.postDelayed(ticker, 2000)
        }
        return v
    }

    override fun onResume() {
        super.onResume()
        refresh()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    /** Internet-check animation state, driven by MainActivity before VPN start. */
    fun setChecking(c: Boolean) {
        checking = c
        if (activity == null || !::powerBtn.isInitialized) return
        powerBtn.isEnabled = !c
        checkSpinner.visibility = if (c) View.VISIBLE else View.GONE
        if (c) {
            powerLabel.text = "Memeriksa koneksi…"
            latencyTv.text = ""
        } else {
            refresh()
        }
    }

    private fun refreshUpstreamLabel() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        statUpstream.text = app.prefs().upstreamLabel()
    }

    private fun specLabel(spec: String): String {
        if (spec.startsWith("preset:")) {
            val w = spec.removePrefix("preset:").toIntOrNull() ?: 0
            return "${Prefs.upstreamName(w)} (${Prefs.upstreamIp(w)})"
        }
        return spec
    }

    /** Rebuild the upstream rows (label + remove button each). Skipped when unchanged. */
    private var lastSpecs: List<String>? = null
    private fun rebuildUpstreamList(force: Boolean = false) {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val specs = app.prefs().upstreamList()
        if (!force && specs == lastSpecs) return
        lastSpecs = specs
        upstreamListBox.removeAllViews()
        if (specs.isEmpty()) {
            val t = TextView(act)
            t.text = "(kosong — tambah upstream dulu)"
            t.setTextColor(0xFF8B93A7.toInt())
            t.textSize = 13f
            upstreamListBox.addView(t)
            return
        }
        specs.forEachIndexed { idx, spec ->
            val row = LinearLayout(act)
            row.orientation = LinearLayout.HORIZONTAL
            val label = TextView(act)
            label.text = "${idx + 1}. ${specLabel(spec)}"
            label.setTextColor(0xFFE8EAF0.toInt())
            label.textSize = 14f
            label.layoutParams = LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            val del = Button(act)
            del.text = "✕"
            del.setOnClickListener { removeUpstream(idx) }
            row.addView(label)
            row.addView(del)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.topMargin = 4
            row.layoutParams = lp
            upstreamListBox.addView(row)
        }
    }

    private fun addUpstreamFromForm() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val specs = app.prefs().upstreamList().toMutableList()
        if (specs.size >= Prefs.MAX_UPSTREAMS) {
            Toast.makeText(act, "Maksimal ${Prefs.MAX_UPSTREAMS} upstream", Toast.LENGTH_SHORT).show()
            return
        }
        val spec = if (addPresetGroup.checkedRadioButtonId == R.id.add_custom) {
            val raw = addCustomEt.text.toString().trim()
            if (!Prefs.parseCustomUpstream(raw).valid) {
                Toast.makeText(act,
                    "Format salah: tls://host, https://host/path, IP atau hostname",
                    Toast.LENGTH_LONG).show()
                return
            }
            raw
        } else {
            val w = if (addPresetGroup.checkedRadioButtonId == R.id.add_google) 1
                else if (addPresetGroup.checkedRadioButtonId == R.id.add_quad9) 2 else 0
            "preset:$w"
        }
        if (specs.contains(spec)) {
            Toast.makeText(act, "Sudah ada di daftar", Toast.LENGTH_SHORT).show()
            return
        }
        specs.add(spec)
        app.prefs().setUpstreamList(specs)
        addCustomEt.setText("")
        rebuildUpstreamList(force = true)
        refreshUpstreamLabel()
    }

    private fun removeUpstream(idx: Int) {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val specs = app.prefs().upstreamList().toMutableList()
        if (specs.size <= 1) {
            Toast.makeText(act, "Minimal 1 upstream", Toast.LENGTH_SHORT).show()
            return
        }
        if (idx < 0 || idx >= specs.size) return
        specs.removeAt(idx)
        app.prefs().setUpstreamList(specs)
        rebuildUpstreamList(force = true)
        refreshUpstreamLabel()
    }

    fun refresh() {
        val act = activity ?: return
        val a = act as MainActivity
        val app = a.app()
        val running = a.isVpnRunning()
        val offline = running && DnsVpnService.networkLost

        if (!running) {
            statusTv.setText(R.string.protected_off)
            statusTv.setTextColor(0xFF8B93A7.toInt())
            latencyTv.text = ""
        } else if (offline) {
            statusTv.text = "OFFLINE — tidak ada internet"
            statusTv.setTextColor(0xFFFBBF24.toInt())
            latencyTv.text = "—"
        } else {
            statusTv.setText(R.string.protected_on)
            statusTv.setTextColor(0xFF4ADE80.toInt())
            // passive latency: EMA of real upstream queries (no extra traffic)
            val ema = DnsVpnService.dnsLatencyEmaMs
            val age = System.currentTimeMillis() - DnsVpnService.dnsLatencyEmaAt
            latencyTv.text = if (ema >= 0 && age < 30000) "${ema}ms" else "—"
        }
        if (!checking) powerLabel.setText(if (running) R.string.tap_to_stop else R.string.tap_to_start)
        // tint the vector power icon (fixes tofu box on devices lacking U+23FB)
        powerBtn.setColorFilter((if (running) 0xFF4ADE80 else 0xFF5B6478).toInt())

        val totals = app.logBus().totalsAll()
        statQueries.text = formatNum(totals[0])
        statBlocked.text = formatNum(totals[1])
        val rate = if (totals[0] == 0L) 0.0 else 100.0 * totals[1] / totals[0]
        statRate.text = String.format("%.1f%%", rate)

        refreshUpstreamLabel()
        val mode = app.prefs().upstreamMode()
        val proto = app.prefs().getProtocol()
        updatingRadio = true
        modeGroup.check(
            if (mode == Prefs.MODE_FASTEST) R.id.mode_fastest
            else if (mode == Prefs.MODE_SEQUENTIAL) R.id.mode_sequential
            else R.id.mode_parallel
        )
        protocolGroup.check(if (proto == 2) R.id.proto_doh else R.id.proto_dot)
        updatingRadio = false
        rebuildUpstreamList()
        uptimeTv.text = if (!running) "" else if (offline) "Menunggu koneksi…" else "VPN active"
        // failover status (static on the service; empty when VPN is off)
        val st = if (running) DnsVpnService.upstreamStatusLine else ""
        upstreamStatusTv.text = st
        val down = st.contains("DOWN")
        upstreamStatusTv.setTextColor((if (down) 0xFFFBBF24 else 0xFF8B93A7).toInt())
    }

    companion object {
        private fun formatNum(n: Long): String {
            if (n >= 1_000_000) return String.format("%.1fM", n / 1_000_000.0)
            if (n >= 1_000) return String.format("%.1fK", n / 1_000.0)
            return n.toString()
        }
    }
}
