package com.netaver.dns.ui

import android.app.Fragment
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView

import com.netaver.dns.DnsVpnService
import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.ProviderCatalog

import java.util.Locale

/** Home tab: power button, stats, and a summary row that opens the Upstream tab. */
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
    private lateinit var upstreamRow: View
    private lateinit var upstreamNames: TextView
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var ticker: Runnable
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
        upstreamRow = v.findViewById(R.id.home_upstream_row)
        upstreamNames = v.findViewById(R.id.home_upstream_names)

        // Watermark below the Upstream card (mockup-approved): brand,
        // italic tagline, and "version" (purple) + versionName (green).
        val versionTv = v.findViewById<TextView>(R.id.home_version_line)
        try {
            val vn = activity!!.packageManager.getPackageInfo(activity!!.packageName, 0).versionName
            if (vn.isNullOrEmpty()) {
                versionTv.visibility = View.GONE
            } else {
                val full = "version $vn"
                val span = SpannableString(full)
                span.setSpan(ForegroundColorSpan(Color.parseColor("#a855f7")), 0, 7, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                span.setSpan(ForegroundColorSpan(Color.parseColor("#22c55e")), 8, full.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                versionTv.text = span
            }
        } catch (e: Exception) {
            versionTv.visibility = View.GONE
        }

        powerBtn.setOnClickListener { (activity as MainActivity).toggleVpn() }
        upstreamRow.setOnClickListener { (activity as MainActivity).openUpstream() }
        v.findViewById<View>(R.id.card_queries).setOnClickListener {
            (activity as MainActivity).openDnsLog(0)
        }
        v.findViewById<View>(R.id.card_blocked).setOnClickListener {
            (activity as MainActivity).openDnsLog(1)
        }

        val app0 = activity!!.application as NetAverApp
        app0.prefs().migrateUpstreamsIfNeeded()

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
            powerLabel.setText(R.string.checking_connection)
            latencyTv.text = ""
        } else {
            refresh()
        }
    }

    private fun refreshUpstreamLabel() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        statUpstream.text = app.prefs().upstreamLabel(act)
    }

    /** Summary row under the stats: provider names + mode, e.g. "Cloudflare, Google · Fastest". */
    private fun updateUpstreamRow() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val p = app.prefs()
        val names = ArrayList<String>()
        for (spec in p.upstreamList()) {
            val id = ProviderCatalog.identify(spec, p.getProtocol())
            val n = if (id.known) id.providerName else getString(R.string.up_custom_name)
            if (!names.contains(n)) names.add(n)
        }
        val shown = names.take(2).joinToString(", ")
        val extra = if (names.size > 2) " +${names.size - 2}" else ""
        val mode = getString(p.modeNameRes())
        upstreamNames.text = if (shown.isEmpty()) mode else "$shown$extra · $mode"
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
            statusTv.setText(R.string.offline_no_internet)
            statusTv.setTextColor(0xFFFBBF24.toInt())
            latencyTv.text = "—"
        } else {
            statusTv.setText(R.string.protected_on)
            statusTv.setTextColor(0xFF4ADE80.toInt())
            // passive latency: EMA of real upstream queries (no extra traffic).
            // Show the last measured value for as long as the VPN is on: with
            // a warm cache, upstream queries can be minutes apart, and the old
            // 30 s freshness gate kept flickering this back to "—" even though
            // the connection was fine (user report 2026-10-24). Mirrors the
            // Upstream tab, which never age-gates its per-provider ping.
            val ema = DnsVpnService.dnsLatencyEmaMs
            latencyTv.text = if (ema >= 0) "${ema}ms" else "—"
        }
        if (!checking) powerLabel.setText(if (running) R.string.tap_to_stop else R.string.tap_to_start)
        // tint the vector power icon (fixes tofu box on devices lacking U+23FB)
        powerBtn.setColorFilter((if (running) 0xFF4ADE80 else 0xFF5B6478).toInt())

        val totals = app.logBus().totalsAll()
        statQueries.text = formatNum(totals[0])
        statBlocked.text = formatNum(totals[1])
        val rate = if (totals[0] == 0L) 0.0 else 100.0 * totals[1] / totals[0]
        statRate.text = String.format(Locale.US, "%.1f%%", rate)

        refreshUpstreamLabel()
        updateUpstreamRow()
        uptimeTv.text = if (!running) "" else if (offline) getString(R.string.waiting_connection) else getString(R.string.vpn_active)
    }

    companion object {
        private fun formatNum(n: Long): String {
            if (n >= 1_000_000) return String.format(Locale.US, "%.1fM", n / 1_000_000.0)
            if (n >= 1_000) return String.format(Locale.US, "%.1fK", n / 1_000.0)
            return n.toString()
        }
    }
}
