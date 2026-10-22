package com.netaver.dns.ui

import android.app.AlertDialog
import android.app.Fragment
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs

import java.util.ArrayList

/**
 * Split tunnel picker: tick apps that must bypass the VPN entirely
 * (direct connection — no filtering, no NetAver DNS, no logs).
 * For apps that refuse to work behind a VPN (banking, games, etc).
 *
 * Changes are STAGED (v2.2.9): ticking/unticking only edits a pending
 * set; nothing is saved or applied until the user presses "Terapkan"
 * and confirms one summary dialog covering both directions (new
 * bypasses + removed bypasses). "Batal" discards the pending set.
 * This protects against accidental taps.
 */
class SplitTunnelFragment : Fragment() {

    /** [systemOnly] = system package without a launcher entry (toggle-gated). */
    private class AppRow(val label: String, val pkg: String, val systemOnly: Boolean = false)

    private lateinit var list: ListView
    private lateinit var search: EditText
    private lateinit var showSystemBox: CheckBox
    private var systemLoaded = false
    private lateinit var bar: View
    private lateinit var barText: TextView
    private lateinit var adapter: SplitAdapter
    private val all = ArrayList<AppRow>()
    /** Working (pending) set shown by the checkboxes. */
    private lateinit var bypassed: MutableSet<String>
    /** Last saved/applied set; diff against [bypassed] drives the bar. */
    private lateinit var saved: MutableSet<String>
    private lateinit var prefs: Prefs
    private val handler = Handler(Looper.getMainLooper())
    private var pendingRestart: Runnable? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_split_tunnel, container, false)
        val app = activity!!.application as NetAverApp
        prefs = app.prefs()
        saved = prefs.splitBypassSet().toMutableSet()
        bypassed = saved.toMutableSet()

        list = v.findViewById(R.id.split_list)
        search = v.findViewById(R.id.split_search)
        showSystemBox = v.findViewById(R.id.split_show_system)
        showSystemBox.isChecked = prefs.showSystemApps()
        showSystemBox.setOnCheckedChangeListener { _, on ->
            prefs.setShowSystemApps(on)
            if (on && !systemLoaded) loadApps() else applyFilter(search.text.toString())
        }
        bar = v.findViewById(R.id.split_bar)
        barText = v.findViewById(R.id.split_bar_text)
        adapter = SplitAdapter()
        list.adapter = adapter
        v.findViewById<Button>(R.id.split_btn_cancel).setOnClickListener { discardPending() }
        v.findViewById<Button>(R.id.split_btn_apply).setOnClickListener { confirmApply() }
        updateBar()

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) { applyFilter(s.toString()) }
        })

        loadApps()
        return v
    }

    private fun loadApps() {
        val includeSystem = prefs.showSystemApps()
        Thread({
            val act = activity ?: return@Thread
            val pm: PackageManager = act.packageManager
            val self = act.packageName
            val i = Intent(Intent.ACTION_MAIN, null)
            i.addCategory(Intent.CATEGORY_LAUNCHER)
            val ris = pm.queryIntentActivities(i, 0)
            val rows = ArrayList<AppRow>()
            val seen = HashSet<String>()
            for (ri in ris) {
                val ai = ri.activityInfo ?: continue
                val pkg = ai.packageName
                if (pkg == self) continue // we always bypass ourselves
                if (!seen.add(pkg)) continue
                val label = ri.loadLabel(pm).toString()
                rows.add(AppRow(label, pkg))
            }
            if (includeSystem) {
                // System packages WITHOUT a launcher entry (services,
                // providers, OEM components) — only shown when the
                // "show system apps" toggle is on.
                try {
                    val installed = pm.getInstalledApplications(0)
                    for (ai in installed) {
                        val pkg = ai.packageName
                        if (pkg == self || seen.contains(pkg)) continue
                        val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 ||
                            (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        if (!isSystem) continue
                        seen.add(pkg)
                        val label = pm.getApplicationLabel(ai).toString()
                        rows.add(AppRow(label, pkg, systemOnly = true))
                    }
                } catch (ignored: Exception) {
                }
            }
            rows.sortWith(compareBy { it.label.lowercase() })
            val a = activity ?: return@Thread
            a.runOnUiThread {
                all.clear()
                all.addAll(rows)
                systemLoaded = includeSystem
                applyFilter(search.text.toString())
            }
        }, "split-apps").start()
    }

    private fun applyFilter(q0: String) {
        val q = q0.trim().lowercase()
        val showSystem = prefs.showSystemApps()
        val show = ArrayList<AppRow>()
        for (r in all) {
            if (r.systemOnly && !showSystem) continue
            if (q.isEmpty() || r.label.lowercase().contains(q)
                || r.pkg.lowercase().contains(q)
            ) {
                show.add(r)
            }
        }
        adapter.setItems(show)
    }

    /** Toggles only edit the pending set — nothing is saved yet. */
    private fun onToggled(pkg: String, checked: Boolean) {
        if (checked) bypassed.add(pkg)
        else bypassed.remove(pkg)
        updateBar()
    }

    private fun pendingDiff(): Pair<Set<String>, Set<String>> {
        val added = bypassed - saved
        val removed = saved - bypassed
        return added to removed
    }

    private fun updateBar() {
        val (added, removed) = pendingDiff()
        val n = added.size + removed.size
        if (n == 0) {
            bar.visibility = View.GONE
        } else {
            bar.visibility = View.VISIBLE
            barText.text = getString(R.string.changes_not_applied_fmt, n)
        }
    }

    private fun discardPending() {
        bypassed = saved.toMutableSet()
        adapter.notifyDataSetChanged()
        updateBar()
    }

    private fun labelOf(pkg: String): String =
        all.firstOrNull { it.pkg == pkg }?.label ?: pkg

    /** One summary dialog for the whole batch, both directions. */
    private fun confirmApply() {
        val act = activity ?: return
        val (added, removed) = pendingDiff()
        if (added.isEmpty() && removed.isEmpty()) return
        val msg = StringBuilder()
        if (added.isNotEmpty()) {
            msg.append(getString(R.string.split_added_header,
                added.joinToString(", ") { labelOf(it) }))
        }
        if (removed.isNotEmpty()) {
            if (msg.isNotEmpty()) msg.append("\n")
            msg.append(getString(R.string.split_removed_header,
                removed.joinToString(", ") { labelOf(it) }))
        }
        msg.append(getString(R.string.split_restart_note))
        AlertDialog.Builder(act)
            .setTitle(R.string.split_apply_title)
            .setMessage(msg.toString())
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.split_apply_yes) { _, _ ->
                prefs.setSplitBypassSet(bypassed)
                saved = bypassed.toMutableSet()
                updateBar()
                scheduleRestart()
            }
            .show()
    }

    /** Restart VPN (debounced) so the change takes effect. */
    private fun scheduleRestart() {
        pendingRestart?.let { handler.removeCallbacks(it) }
        pendingRestart = Runnable {
            val act = activity as? MainActivity ?: return@Runnable
            if (act.isVpnRunning()) {
                act.restartVpn()
                Toast.makeText(act, R.string.split_restarted_toast,
                    Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(act, R.string.split_saved_toast,
                    Toast.LENGTH_SHORT).show()
            }
        }
        pendingRestart?.let { handler.postDelayed(it, 2000) }
    }

    override fun onDestroyView() {
        pendingRestart?.let { handler.removeCallbacks(it) }
        super.onDestroyView()
    }

    private inner class SplitAdapter : BaseAdapter() {
        private val items = ArrayList<AppRow>()

        fun setItems(rows: List<AppRow>) {
            items.clear()
            items.addAll(rows)
            notifyDataSetChanged()
        }

        override fun getCount(): Int = items.size
        override fun getItem(p: Int): Any = items[p]
        override fun getItemId(p: Int): Long = p.toLong()

        override fun getView(pos: Int, cv: View?, parent: ViewGroup): View {
            var row = cv
            if (row == null) {
                row = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_split_app, parent, false)
            }
            val r = items[pos]
            val label: TextView = row.findViewById(R.id.split_label)
            val pkg: TextView = row.findViewById(R.id.split_pkg)
            val check: CheckBox = row.findViewById(R.id.split_check)
            label.text = r.label
            pkg.text = if (r.systemOnly) r.pkg + " · sistem" else r.pkg
            check.setOnCheckedChangeListener(null)
            check.isChecked = bypassed.contains(r.pkg)
            check.setOnCheckedChangeListener { _, isChecked -> onToggled(r.pkg, isChecked) }
            // tapping the row toggles too
            row.setOnClickListener { check.toggle() }
            return row
        }
    }
}
