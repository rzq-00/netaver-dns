package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.Switch
import android.widget.TextView

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.log.Entries
import com.netaver.dns.net.GeoIp
import com.netaver.dns.util.FirewallManager

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Full-page detail for one app: firewall switch (ON = internet allowed),
 * its DNS query log (tap a row for detail) and its connections.
 * Opened from AppsFragment; back returns to the app list.
 */
class AppDetailFragment : Fragment() {
    private lateinit var appName: String
    private lateinit var icon: TextView
    private lateinit var name: TextView
    private lateinit var stats: TextView
    private lateinit var dot: TextView
    private lateinit var fwState: TextView
    private lateinit var empty: TextView
    private lateinit var fwSwitch: Switch
    private lateinit var dnsList: LinearLayout
    private lateinit var connList: LinearLayout
    private lateinit var connHeader: TextView
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var ticker: Runnable
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private var filter = 0 // 0=all 1=blocked 2=allowed 3=bypass (mirip DNS Log)

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_app_detail, container, false)
        appName = if (arguments != null) arguments!!.getString(ARG_APP, "") else ""
        icon = v.findViewById(R.id.detail_icon)
        name = v.findViewById(R.id.detail_name)
        stats = v.findViewById(R.id.detail_stats)
        dot = v.findViewById(R.id.detail_dot)
        fwState = v.findViewById(R.id.detail_fw_state)
        fwSwitch = v.findViewById(R.id.detail_fw)
        dnsList = v.findViewById(R.id.detail_dns_list)
        connList = v.findViewById(R.id.detail_conn_list)
        connHeader = v.findViewById(R.id.detail_conn_header)
        empty = v.findViewById(R.id.detail_empty)

        val back: Button = v.findViewById(R.id.detail_back)
        back.setOnClickListener { fragmentManager?.popBackStack() }

        val rg: RadioGroup = v.findViewById(R.id.detail_filter_group)
        rg.setOnCheckedChangeListener { _, checkedId ->
            filter = if (checkedId == R.id.detail_f_blocked) 1
                else if (checkedId == R.id.detail_f_allowed) 2
                else if (checkedId == R.id.detail_f_bypass) 3 else 0
            refreshNow()
        }

        icon.text = if (appName.isEmpty()) "?" else appName.substring(0, 1).uppercase()
        name.text = appName

        ticker = Runnable {
            refreshNow()
            handler.postDelayed(ticker, 3000)
        }
        return v
    }

    override fun onResume() {
        super.onResume()
        refreshNow()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun refreshNow() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val fw: FirewallManager = app.firewall()

        // find current stat for this app
        var stat: Entries.AppStat? = null
        for (s in app.logBus().appStats()) {
            if (s.app == appName) {
                stat = s
                break
            }
        }
        val uid = stat?.uid ?: -100
        val blocked = uid >= 0 && fw.isBlocked(uid)

        stats.text = if (stat == null) getString(R.string.no_activity_yet)
        else getString(R.string.app_stats_short_fmt, stat.queries, stat.blocked, stat.conns)
        dot.setTextColor((if (blocked) 0xFFF87171 else 0xFF4ADE80).toInt())

        // Switch ON = internet allowed (intuitive). OFF = blocked by firewall.
        fwSwitch.setOnCheckedChangeListener(null)
        fwSwitch.isChecked = !blocked
        fwSwitch.isEnabled = uid >= 0
        fwState.setText(if (blocked) R.string.fw_blocked_state else R.string.fw_allowed_state)
        fwState.setTextColor((if (blocked) 0xFFF87171 else 0xFF4ADE80).toInt())
        fwSwitch.setOnCheckedChangeListener { _, checked ->
            if (uid < 0) return@setOnCheckedChangeListener
            fw.setRule(uid, if (checked) FirewallManager.ALLOW else FirewallManager.BLOCK)
            refreshNow()
        }

        // DNS queries (tap row -> detail dialog). The filter is applied
        // while collecting (up to 100 MATCHING entries), not after taking
        // the newest N — busy apps no longer crowd out their blocked rows.
        val dns = app.logBus().dnsForApp(appName, 100, filter)
        dnsList.removeAllViews()
        var dnsShown = 0
        for (d in dns) {
            val row = DnsRow.inflate(dnsList)
            DnsRow.bind(row, d)
            row.setOnClickListener { DnsDetailDialog.show(act, d) }
            dnsList.addView(row)
            dnsShown++
        }

        // Connections (same filter; the section is hidden under Bypass,
        // which is a DNS-only concept).
        val conns = app.logBus().connsForApp(appName, 100, if (filter == 3) 0 else filter)
        connList.removeAllViews()
        var connShown = 0
        for (c in conns) {
            if (filter == 3) continue
            val tv = TextView(act)
            val flag = GeoIp.flagFor(c.countryCode)
            tv.text = (if (c.blocked) "🚫 " else if (flag.isEmpty()) "" else "$flag ") +
                "${c.proto} ${c.dest} · ${fmt.format(Date(c.time))}"
            tv.setTextColor((if (c.blocked) 0xFFF87171 else 0xFFF1F5F9).toInt())
            tv.textSize = 13f
            tv.setPadding(0, 8, 0, 8)
            connList.addView(tv)
            connShown++
        }
        connHeader.visibility = if (filter == 3) View.GONE else View.VISIBLE
        connList.visibility = if (filter == 3) View.GONE else View.VISIBLE

        empty.visibility =
            if (dnsShown == 0 && (filter == 3 || connShown == 0)) View.VISIBLE else View.GONE
    }

    companion object {
        private const val ARG_APP = "app"

        @JvmStatic
        fun newInstance(appName: String): AppDetailFragment {
            val f = AppDetailFragment()
            val b = Bundle()
            b.putString(ARG_APP, appName)
            f.arguments = b
            return f
        }
    }
}
