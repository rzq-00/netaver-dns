package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.RadioGroup
import android.widget.TextView

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.log.Entries
import com.netaver.dns.log.LogBus

import java.util.ArrayList
import java.util.concurrent.Executors

/** Live DNS query log with All/Blocked/Allowed/Bypass filter + text search. */
class DnsLogFragment : Fragment() {
    private lateinit var list: ListView
    private lateinit var empty: TextView
    private lateinit var adapter: DnsAdapter
    private var filter = 0 // 0=all 1=blocked 2=allowed 3=bypass
    private var query = ""
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var listener: LogBus.Listener
    private lateinit var throttledRefresh: Runnable
    private var refreshScheduled = false
    /** DB search runs off the main thread; seq drops stale results. */
    private val searchIo = Executors.newSingleThreadExecutor { r ->
        Thread(r, "dns-search").apply { isDaemon = true }
    }
    private var searchSeq = 0

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_dns_log, container, false)
        list = v.findViewById(R.id.dns_list)
        empty = v.findViewById(R.id.dns_empty)
        adapter = DnsAdapter()
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            val act = activity ?: return@setOnItemClickListener
            val e = adapter.getItem(pos) as Entries.DnsEntry
            DnsDetailDialog.show(act, e)
        }

        val rg: RadioGroup = v.findViewById(R.id.dns_filter_group)
        rg.setOnCheckedChangeListener { _, checkedId ->
            filter = if (checkedId == R.id.f_blocked) 1
                else if (checkedId == R.id.f_allowed) 2
                else if (checkedId == R.id.f_bypass) 3 else 0
            refreshNow()
        }

        val search: EditText = v.findViewById(R.id.dns_search)
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s.toString().trim().lowercase()
                refreshNow()
            }
        })

        throttledRefresh = Runnable {
            refreshScheduled = false
            refreshNow()
        }
        listener = LogBus.Listener {
            // while searching, results are on-demand (no live refresh -> no useless DB hits);
            // filtered views (blocked/allowed/bypass) still refresh, from the DB.
            if (query.isEmpty() && !refreshScheduled) {
                refreshScheduled = true
                handler.postDelayed(throttledRefresh, 2000) // battery: max ~1 refresh/2s
            }
        }
        return v
    }

    override fun onResume() {
        super.onResume()
        val app = activity!!.application as NetAverApp
        app.logBus().addListener(listener)
        refreshNow()
    }

    override fun onPause() {
        super.onPause()
        val app = activity!!.application as NetAverApp
        app.logBus().removeListener(listener)
        handler.removeCallbacks(throttledRefresh)
        refreshScheduled = false
    }

    private fun refreshNow() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        if (query.isNotEmpty() || filter != 0) {
            // Searching or filtered (blocked/allowed/bypass): prefer the full
            // stored history (1 week) from the DB. If the DB is empty or the
            // read fails, fall back to filtering the in-memory ring so the
            // screen never goes blank while the cause is being diagnosed.
            val seq = ++searchSeq
            val q = query
            val f = filter
            searchIo.execute {
                var res = app.logStore().searchDns(q, f, 300)
                if (res.isEmpty()) {
                    val ring = app.logBus().dnsSnapshot()
                    val fb = ArrayList<Entries.DnsEntry>()
                    for (i in ring.size - 1 downTo 0) {
                        if (fb.size >= 300) break
                        val e = ring[i]
                        if (f == 1 && !e.blocked) continue
                        if (f == 2 && e.blocked) continue
                        if (f == 3 && !e.isBypass) continue
                        val lc = q.lowercase()
                        if (lc.isNotEmpty()
                            && !e.domain.lowercase().contains(lc)
                            && !e.resolvedIp.lowercase().contains(lc)
                            && !e.app.lowercase().contains(lc)
                            && !e.matchInfo.lowercase().contains(lc)
                        ) continue
                        fb.add(e)
                    }
                    if (fb.isNotEmpty()) res = fb
                }
                handler.post {
                    if (seq != searchSeq || activity == null) return@post
                    adapter.setItems(res)
                    empty.visibility = if (res.isEmpty()) View.VISIBLE else View.GONE
                    list.visibility = if (res.isEmpty()) View.GONE else View.VISIBLE
                }
            }
            return
        }
        searchSeq++ // invalidate any in-flight search
        // Unfiltered live view (all): in-memory ring is fastest.
        val all = app.logBus().dnsSnapshot()
        val show = ArrayList<Entries.DnsEntry>()
        for (i in all.size - 1 downTo 0) {
            if (show.size >= 300) break
            show.add(all[i])
        }
        adapter.setItems(show)
        empty.visibility = if (show.isEmpty()) View.VISIBLE else View.GONE
        list.visibility = if (show.isEmpty()) View.GONE else View.VISIBLE
    }

    private class DnsAdapter : BaseAdapter() {
        private var items: List<Entries.DnsEntry> = ArrayList()

        fun setItems(items: List<Entries.DnsEntry>) {
            this.items = items
            notifyDataSetChanged()
        }

        override fun getCount(): Int = items.size
        override fun getItem(i: Int): Any = items[i]
        override fun getItemId(i: Int): Long = i.toLong()

        override fun getView(pos: Int, cv: View?, parent: ViewGroup): View {
            var row = cv
            if (row == null) row = DnsRow.inflate(parent)
            DnsRow.bind(row, items[pos])
            return row
        }
    }
}
