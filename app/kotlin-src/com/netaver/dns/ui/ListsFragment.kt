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
            updBtn.text = "Updating…"
            Toast.makeText(act, "Updating blocklists…", Toast.LENGTH_SHORT).show()
            Thread({
                mgr.refreshCustomLists()
                val a = activity ?: return@Thread
                a.runOnUiThread {
                    updBtn.isEnabled = true
                    updBtn.setText(R.string.update_lists)
                    refreshNow()
                    val total = mgr.blocklist().size()
                    Toast.makeText(a, "Done: $total rules active", Toast.LENGTH_SHORT).show()
                }
            }, "bl-update").start()
        }

        mgr.addChangeListener {
            val a = activity ?: return@addChangeListener
            a.runOnUiThread { refreshNow() }
        }

        val rulesBtn: Button = v.findViewById(R.id.custom_rules_btn)
        rulesBtn.text = getString(R.string.custom_rules) +
            " (" + app.customRules().count() + ")"
        rulesBtn.setOnClickListener { showRulesDialog(rulesBtn) }

        refreshNow()
        return v
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
                    "${counts[0]} block, ${counts[1]} allow rules active",
                    Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun refreshNow() {
        val rows = ArrayList<Row>()
        rows.add(Row("Built-in Ads & Trackers", "bundled",
            prefs.builtinEnabled(), ruleCount("bundled"), true, null))
        for (cl in mgr.customLists()) {
            rows.add(Row(cl.name, cl.url, cl.enabled, ruleCount(cl.url), false,
                listError(cl.url)))
        }
        adapter.setRows(rows, mgr, prefs, Runnable { refreshNow() })
        val total = mgr.blocklist().size()
        val st = prefs.lastListStatus()
        summary.text = "Blocklists · $total rules active" +
            if (st.isEmpty()) "" else " · $st"
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

    private fun showAddDialog() {
        val act = activity!!
        val nameEt = EditText(act)
        nameEt.hint = "Name, e.g. Hagezi Multi PRO"
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
            .setTitle("Add custom blocklist")
            .setView(ll)
            .setPositiveButton(R.string.add) { _, _ ->
                var name = nameEt.text.toString().trim()
                val url = urlEt.text.toString().trim()
                if (url.isEmpty() || !(url.startsWith("http://") || url.startsWith("https://"))) {
                    Toast.makeText(act, "Invalid URL", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (name.isEmpty()) name = url
                val cls = mgr.customLists()
                cls.add(BlocklistManager.CustomList(name, url, true))
                mgr.saveCustomLists(cls)
                refreshNow()
                Toast.makeText(act, "Added. Tap Update to download.",
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
            val status: String
            if (!r.enabled) {
                status = "Disabled — turn on, then tap Update"
            } else if (r.error != null) {
                status = "Update failed (" + r.error + ") — tap Update to retry"
            } else if (r.rules == 0 && !r.isBuiltin) {
                status = "Not downloaded — tap Update"
            } else {
                status = r.rules.toString() + " rules" + if (r.isBuiltin) " · bundled" else ""
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
                        .setTitle("Delete list?")
                        .setMessage(r.name)
                        .setPositiveButton("Delete") { _, _ ->
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
