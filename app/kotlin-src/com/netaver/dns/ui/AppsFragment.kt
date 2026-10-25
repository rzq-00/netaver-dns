package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.CheckBox
import android.widget.ListView
import android.widget.Switch
import android.widget.TextView

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.log.Entries
import com.netaver.dns.util.FirewallManager

import java.util.ArrayList
import java.util.Locale

/**
 * Per-app network activity + firewall switches (RethinkDNS-style).
 * Tap an app to see its recent connections with country flags.
 */
class AppsFragment : Fragment() {
    private lateinit var list: ListView
    private lateinit var empty: TextView
    private lateinit var adapter: AppsAdapter
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var ticker: Runnable

    /** Installed system packages (one row per UID), loaded once off-thread. */
    @Volatile
    private var systemRows: List<Entries.AppStat>? = null
    private var systemLoadStarted = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_apps, container, false)
        list = v.findViewById(R.id.apps_list)
        empty = v.findViewById(R.id.apps_empty)
        val app = activity!!.application as NetAverApp
        val showSystemBox: CheckBox = v.findViewById(R.id.apps_show_system)
        showSystemBox.isChecked = app.prefs().showSystemApps()
        showSystemBox.setOnCheckedChangeListener { _, on ->
            app.prefs().setShowSystemApps(on)
            refreshNow()
        }
        adapter = AppsAdapter(app.firewall())
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            val s = adapter.getItem(pos) as Entries.AppStat
            (activity as? MainActivity)?.openAppDetail(s.app)
        }
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
        val allStats = app.logBus().appStats()
        val stats: List<Entries.AppStat>
        if (app.prefs().showSystemApps()) {
            // Traffic rows first; then installed system packages that have
            // NO traffic yet — so the firewall switch can pre-block them.
            ensureSystemRowsLoaded()
            val merged = ArrayList(allStats)
            val haveUids = HashSet<Int>()
            for (s in allStats) if (s.uid >= 0) haveUids.add(s.uid)
            val extra = systemRows
            if (extra != null) {
                val add = extra.filter { it.uid >= 0 && !haveUids.contains(it.uid) }
                    .sortedBy { it.app.lowercase() }
                merged.addAll(add)
            }
            stats = merged
        } else {
            // System rows = uid below FIRST_APPLICATION_UID (incl. the -1
            // "System" bucket); hidden unless the toggle is on.
            stats = allStats.filter { it.uid >= 10000 }
        }
        adapter.setItems(stats)
        empty.visibility = if (stats.isEmpty()) View.VISIBLE else View.GONE
        list.visibility = if (stats.isEmpty()) View.GONE else View.VISIBLE
    }

    /** Load installed system packages once (one row per UID; shared UIDs collapse). */
    private fun ensureSystemRowsLoaded() {
        if (systemRows != null || systemLoadStarted) return
        systemLoadStarted = true
        val act = activity ?: return
        val pm = act.packageManager
        val self = act.packageName
        Thread({
            val rows = ArrayList<Entries.AppStat>()
            val seenUid = HashSet<Int>()
            try {
                val installed = pm.getInstalledApplications(0)
                for (ai in installed) {
                    if (ai.packageName == self) continue
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 ||
                        (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (!isSystem) continue
                    if (!seenUid.add(ai.uid)) continue // shared UID: one row
                    val label = pm.getApplicationLabel(ai).toString()
                    val s = Entries.AppStat(label)
                    s.uid = ai.uid
                    s.installedOnly = true
                    rows.add(s)
                }
            } catch (ignored: Exception) {
            }
            systemRows = rows
            handler.post { refreshNow() }
        }, "apps-system").start()
    }

    private class AppsAdapter(private val fw: FirewallManager) : BaseAdapter() {
        private var items: List<Entries.AppStat> = ArrayList()

        fun setItems(items: List<Entries.AppStat>) {
            this.items = items
            notifyDataSetChanged()
        }

        override fun getCount(): Int = items.size
        override fun getItem(i: Int): Any = items[i]
        override fun getItemId(i: Int): Long = i.toLong()

        override fun getView(pos: Int, cv: View?, parent: ViewGroup): View {
            var row = cv
            if (row == null) {
                row = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_app, parent, false)
            }
            val s = items[pos]
            val icon: TextView = row.findViewById(R.id.item_icon)
            val name: TextView = row.findViewById(R.id.item_name)
            val sub: TextView = row.findViewById(R.id.item_sub)
            val dot: TextView = row.findViewById(R.id.item_dot)
            val fwSwitch: Switch = row.findViewById(R.id.item_fw)
            icon.text = if (s.app.isEmpty()) "?" else s.app.substring(0, 1).uppercase()
            name.text = s.app
            sub.text = if (s.installedOnly) parent.context.getString(R.string.app_no_activity_system)
                else parent.context.getString(R.string.app_stats_fmt,
                    s.queries, s.blocked, s.conns, fmtBytes(s.bytesUp + s.bytesDown))
            val isBlocked = s.uid >= 0 && fw.isBlocked(s.uid)
            val color = if (isBlocked) 0xFFF87171
                else if (s.blocked > s.queries / 2 && s.queries > 10) 0xFFF87171
                else if (s.queries + s.conns > 0) 0xFF4ADE80 else 0xFF8B93A7
            dot.setTextColor(color.toInt())
            // firewall switch: ON = internet allowed (intuitive), OFF = blocked
            fwSwitch.setOnCheckedChangeListener(null)
            fwSwitch.isChecked = !isBlocked
            fwSwitch.isEnabled = s.uid >= 0
            val uid = s.uid
            fwSwitch.setOnCheckedChangeListener { _, checked ->
                fw.setRule(uid, if (checked) FirewallManager.ALLOW else FirewallManager.BLOCK)
                notifyDataSetChanged()
            }
            return row
        }

        companion object {
            private fun fmtBytes(b: Long): String {
                if (b >= (1 shl 20)) return String.format(Locale.US, "%.1f MB", b / (1 shl 20).toFloat())
                if (b >= (1 shl 10)) return String.format(Locale.US, "%.0f KB", b / (1 shl 10).toFloat())
                return "$b B"
            }
        }
    }
}
