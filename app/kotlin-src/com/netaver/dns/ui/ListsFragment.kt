package com.netaver.dns.ui

import android.app.AlertDialog
import android.app.Fragment
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.dns.BlocklistManager
import com.netaver.dns.util.Prefs

import java.util.ArrayList

/** Blocklist manager: bundled + custom URLs (Hagezi etc.). */
class ListsFragment : Fragment() {
    private lateinit var list: ListView
    private lateinit var summary: TextView
    private lateinit var adapter: ListsAdapter
    private lateinit var mgr: BlocklistManager
    private lateinit var prefs: Prefs

    // M5 fix: the change listener lives in a named field so onDestroyView
    // can unregister this exact instance (an inline lambda could never be
    // removed, and the manager would retain the fragment forever).
    // M4 fix: the posted body re-checks isAdded before touching views.
    private val listsChangedListener = Runnable {
        val a = activity ?: return@Runnable
        a.runOnUiThread { if (isAdded) refreshNow() }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_lists, container, false)
        val act = activity!!
        val app = act.application as NetAverApp
        mgr = app.blocklists()
        prefs = app.prefs()

        list = v.findViewById(R.id.lists_list)
        summary = v.findViewById(R.id.lists_summary)
        adapter = ListsAdapter()
        list.adapter = adapter

        val addBtn: Button = v.findViewById(R.id.add_list_btn)
        addBtn.setOnClickListener { showAddDialog() }

        val updBtn: Button = v.findViewById(R.id.update_lists_btn)
        updBtn.setOnClickListener {
            updBtn.isEnabled = false
            updBtn.setText(R.string.updating)
            Toast.makeText(act, R.string.updating_blocklists, Toast.LENGTH_SHORT).show()
            Thread({
                mgr.refreshCustomLists()
                val a = activity ?: return@Thread
                a.runOnUiThread {
                    // M4 fix: the tab may have been switched away while the
                    // refresh ran; touching views/getString now would crash.
                    if (!isAdded) return@runOnUiThread
                    updBtn.isEnabled = true
                    updBtn.setText(R.string.update_lists)
                    refreshNow()
                    val total = mgr.blocklist().size()
                    Toast.makeText(a, getString(R.string.update_done_fmt, total), Toast.LENGTH_SHORT).show()
                }
            }, "bl-update").start()
        }

        mgr.addChangeListener(listsChangedListener)

        val rulesBtn: Button = v.findViewById(R.id.custom_rules_btn)
        rulesBtn.text = getString(R.string.custom_rules) +
            " (" + app.customRules().count() + ")"
        rulesBtn.setOnClickListener { showRulesDialog(rulesBtn) }

        refreshNow()
        return v
    }

    override fun onDestroyView() {
        // M5 fix: unregister so BlocklistManager doesn't retain this fragment
        mgr.removeChangeListener(listsChangedListener)
        super.onDestroyView()
    }

    private fun showRulesDialog(rulesBtn: Button) {
        val act = activity!!
        val app = act.application as NetAverApp
        val et = EditText(act)
        et.setText(app.prefs().customRules())
        et.setHint(R.string.custom_rules_hint)
        et.setTextColor(0xFFF1F5F9.toInt())
        et.setHintTextColor(0xFF5B6478.toInt())
        et.minLines = 10
        et.gravity = Gravity.TOP
        et.typeface = Typeface.MONOSPACE
        // A bare programmatic EditText inherits the theme's large default
        // text size — on the user's device the rules editor rendered huge
        // (long domains wrapped mid-word). Pin a compact editor size.
        et.textSize = 13f
        val sv = ScrollView(act)
        sv.setPadding(40, 20, 40, 0)
        sv.addView(et)
        AlertDialog.Builder(act)
            .setTitle(R.string.custom_rules_title)
            .setView(sv)
            .setPositiveButton(R.string.save) { _, _ ->
                val text = et.text.toString()
                app.prefs().setCustomRules(text)
                val counts = app.customRules().setText(text)
                rulesBtn.text = getString(R.string.custom_rules) +
                    " (" + app.customRules().count() + ")"
                Toast.makeText(act,
                    getString(R.string.rules_active_fmt, counts[0], counts[1]),
                    Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun refreshNow() {
        // M4 fix: async completions can land after this fragment detached;
        // getString() below would throw IllegalStateException.
        if (!isAdded) return
        val rows = ArrayList<Row>()
        rows.add(Row(getString(R.string.builtin_list_name), "bundled",
            prefs.builtinEnabled(), ruleCount("bundled"), true, null))
        for (cl in mgr.customLists()) {
            rows.add(Row(cl.name, cl.url, cl.enabled, ruleCount(cl.url), false,
                listError(cl.url)))
        }
        adapter.setRows(rows, mgr, prefs, Runnable { refreshNow() })
        val total = mgr.blocklist().size()
        val st = statusLine()
        summary.text = getString(R.string.lists_summary_fmt, total) +
            if (st.isEmpty()) "" else " · $st"
        fitListHeight()
    }

    /** Phrase the stored refresh outcome in the CURRENT language. The
     * stored value is raw JSON (counts + timestamp), never a finished
     * sentence; a sentence stored by an older build is ignored on
     * purpose - it kept its original language on screen. */
    private fun statusLine(): String {
        val raw = prefs.lastListStatusJson()
        if (raw.isEmpty()) return ""
        return try {
            val o = org.json.JSONObject(raw)
            val parts = ArrayList<String>()
            val u = o.optInt("u")
            val n = o.optInt("n")
            val f = o.optInt("f")
            if (u > 0) parts.add(getString(R.string.status_updated_fmt, u))
            if (n > 0) parts.add(getString(R.string.status_uptodate_fmt, n))
            if (f > 0) parts.add(getString(R.string.lists_failed_fmt, f))
            val body = if (parts.isEmpty()) getString(R.string.no_active_lists)
                else parts.joinToString(" · ")
            val hhmm = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
                .format(java.util.Date(o.optLong("ts")))
            body + " · " + getString(R.string.checked_fmt, hhmm)
        } catch (e: Exception) {
            ""
        }
    }

    private fun listError(source: String): String? {
        for (li in mgr.listInfos()) {
            if (li.source == source) return li.error
        }
        return null
    }

    private fun ruleCount(source: String): Int {
        for (li in mgr.listInfos()) {
            if (li.source == source) return li.rules
        }
        return 0
    }

    /** Lists fix (issue #1): the list used to stretch and push the buttons
     * to the bottom. Cap its height at its content height (max ~300dp) so
     * the action buttons sit right below the lists. */
    private fun fitListHeight() {
        val count = adapter.count
        if (count == 0) {
            list.layoutParams.height = 0
            list.requestLayout()
            return
        }
        // U-N7: measure EVERY row and sum the heights — rows whose status
        // text wraps are taller than row 0, and the old row0*count
        // estimate undershot and clipped the bottom rows.
        val wSpec = View.MeasureSpec.makeMeasureSpec(
            resources.displayMetrics.widthPixels, View.MeasureSpec.AT_MOST)
        val hSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        var h = list.dividerHeight * (count - 1)
        for (i in 0 until count) {
            val row = adapter.getView(i, null, list)
            row.measure(wSpec, hSpec)
            h += row.measuredHeight
        }
        val cap = (300 * resources.displayMetrics.density).toInt()
        if (h > cap) h = cap
        if (list.layoutParams.height != h) {
            list.layoutParams.height = h
        }
        list.requestLayout()
    }

    private fun showAddDialog() {
        val act = activity!!
        val nameEt = EditText(act)
        nameEt.setHint(R.string.list_name_hint)
        nameEt.setTextColor(0xFFF1F5F9.toInt())
        nameEt.setHintTextColor(0xFF5B6478.toInt())
        val urlEt = EditText(act)
        urlEt.hint = getString(R.string.list_url_hint)
        urlEt.setTextColor(0xFFF1F5F9.toInt())
        urlEt.setHintTextColor(0xFF5B6478.toInt())
        val ll = LinearLayout(act)
        ll.orientation = LinearLayout.VERTICAL
        ll.setPadding(40, 20, 40, 0)
        ll.addView(nameEt)
        ll.addView(urlEt)
        AlertDialog.Builder(act)
            .setTitle(R.string.add_list_title)
            .setView(ll)
            .setPositiveButton(R.string.add) { _, _ ->
                var name = nameEt.text.toString().trim()
                val url = urlEt.text.toString().trim()
                if (url.isEmpty()) {
                    Toast.makeText(act, R.string.invalid_url, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (!url.startsWith("https://", ignoreCase = true)) {
                    Toast.makeText(act, R.string.list_https_only, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                if (url.contains(';') || url.contains('|') || url.any { it.isWhitespace() }) {
                    // N3/U-N6: ';' and '|' are the stored format's
                    // delimiters — such a URL saves fine but re-parses
                    // truncated/disabled on the next read (the import
                    // path drops these for exactly this reason)
                    Toast.makeText(act, R.string.invalid_url, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (name.isEmpty()) name = url
                val cls = mgr.customLists()
                cls.add(BlocklistManager.CustomList(name, url, true))
                mgr.saveCustomLists(cls)
                refreshNow()
                Toast.makeText(act, R.string.added_update_hint,
                    Toast.LENGTH_LONG).show()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    class Row(
        val name: String,
        val source: String,
        var enabled: Boolean,
        val rules: Int,
        val isBuiltin: Boolean,
        val error: String?
    )

    private class ListsAdapter : BaseAdapter() {
        private var rows: List<Row> = ArrayList()
        private lateinit var mgr: BlocklistManager
        private lateinit var prefs: Prefs
        private var onChange: Runnable? = null

        fun setRows(rows: List<Row>, mgr: BlocklistManager, prefs: Prefs, onChange: Runnable) {
            this.rows = rows
            this.mgr = mgr
            this.prefs = prefs
            this.onChange = onChange
            notifyDataSetChanged()
        }

        override fun getCount(): Int = rows.size
        override fun getItem(i: Int): Any = rows[i]
        override fun getItemId(i: Int): Long = i.toLong()

        override fun getView(pos: Int, cv: View?, parent: ViewGroup): View {
            var row = cv
            if (row == null) {
                row = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_blocklist, parent, false)
            }
            val r = rows[pos]
            val name: TextView = row.findViewById(R.id.item_name)
            val sub: TextView = row.findViewById(R.id.item_sub)
            val sw: Switch = row.findViewById(R.id.item_switch)
            name.text = r.name
            val ctx = parent.context
            val status: String
            if (!r.enabled) {
                status = ctx.getString(R.string.status_disabled)
            } else if (r.error != null) {
                val errText = if (r.error == BlocklistManager.ERR_HTTPS_ONLY)
                    ctx.getString(R.string.list_https_only) else r.error
                status = ctx.getString(R.string.status_failed_fmt, errText)
            } else if (r.rules == 0 && !r.isBuiltin) {
                status = ctx.getString(R.string.status_not_downloaded)
            } else {
                status = if (r.isBuiltin) ctx.getString(R.string.status_rules_bundled_fmt, r.rules)
                    else ctx.getString(R.string.status_rules_fmt, r.rules)
            }
            sub.text = status
            sw.setOnCheckedChangeListener(null)
            sw.isChecked = r.enabled
            sw.setOnCheckedChangeListener { _, checked ->
                r.enabled = checked
                if (r.isBuiltin) {
                    prefs.setBuiltinEnabled(checked)
                } else {
                    val cls = mgr.customLists()
                    for (cl in cls) {
                        if (cl.url == r.source) cl.enabled = checked
                    }
                    mgr.saveCustomLists(cls)
                }
                // reload quickly off-main
                Thread({
                    mgr.loadBundled()
                    mgr.refreshCustomLists()
                }, "bl-toggle").start()
                onChange?.run()
            }
            // long-press to delete custom lists
            if (!r.isBuiltin) {
                row.setOnLongClickListener { v ->
                    AlertDialog.Builder(v.context)
                        .setTitle(R.string.delete_list_title)
                        .setMessage(r.name)
                        .setPositiveButton(R.string.delete) { _, _ ->
                            val cls = mgr.customLists()
                            cls.removeIf { cl -> cl.url == r.source }
                            mgr.saveCustomLists(cls)
                            onChange?.run()
                        }
                        .setNegativeButton(R.string.cancel, null)
                        .show()
                    true
                }
            } else {
                row.setOnLongClickListener(null)
            }
            return row
        }
    }
}
