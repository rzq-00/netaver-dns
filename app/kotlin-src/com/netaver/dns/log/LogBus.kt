package com.netaver.dns.log

import com.netaver.dns.util.DebugCapture

import java.util.ArrayDeque
import java.util.ArrayList
import java.util.HashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-memory ring buffers for logs. Battery-friendly: no disk I/O on the
 * packet path, UI pulls snapshots at its own pace.
 */
class LogBus {
    fun interface Listener {
        fun onLogsChanged()
    }

    private val dnsLog = ArrayDeque<Entries.DnsEntry>()
    private val connLog = ArrayDeque<Entries.ConnEntry>()
    private val listeners = CopyOnWriteArrayList<Listener>()
    private var store: LogStore? = null // optional SQLite backing store (persistence across restarts)
    private var debugCapture: DebugCapture? = null // optional: receives a copy of every event while capturing

    private var totalQueries = 0L
    private var totalBlocked = 0L

    // All-time cumulative counters for Home (v2.2.10): seeded at app start
    // (first run from stored history, later from Prefs), incremented per
    // query, flushed to Prefs via the sink every 50 queries and on demand.
    private val allQueries = java.util.concurrent.atomic.AtomicLong(0)
    private val allBlocked = java.util.concurrent.atomic.AtomicLong(0)
    private var totalsSink: ((Long, Long) -> Unit)? = null
    private var addsSinceFlush = 0

    companion object {
        private const val MAX_DNS = 1000
        private const val MAX_CONN = 500
    }

    /** Attach the persistent store; entries added afterwards are saved to disk. */
    @Synchronized
    fun setStore(s: LogStore?) {
        store = s
    }

    /** Attach debug capture; entries added afterwards are also recorded for analysis. */
    @Synchronized
    fun setDebugCapture(d: DebugCapture?) {
        debugCapture = d
    }

    /**
     * Bulk-load entries restored from disk (oldest-first). Does NOT re-save
     * them to the store.
     */
    @Synchronized
    fun restore(dns: List<Entries.DnsEntry>, conns: List<Entries.ConnEntry>) {
        for (e in dns) {
            if (dnsLog.size >= MAX_DNS) dnsLog.pollFirst()
            dnsLog.addLast(e)
            totalQueries++
            if (e.blocked) totalBlocked++
        }
        for (e in conns) {
            if (connLog.size >= MAX_CONN) connLog.pollFirst()
            connLog.addLast(e)
        }
        notifyChanged()
    }

    @Synchronized
    fun addDns(e: Entries.DnsEntry) {
        if (dnsLog.size >= MAX_DNS) dnsLog.pollFirst()
        dnsLog.addLast(e)
        totalQueries++
        if (e.blocked) totalBlocked++
        allQueries.incrementAndGet()
        if (e.blocked) allBlocked.incrementAndGet()
        if (++addsSinceFlush >= 50) flushTotals()
        store?.saveDns(e)
        debugCapture?.onDns(e)
        notifyChanged()
    }

    @Synchronized
    fun addConn(e: Entries.ConnEntry) {
        if (connLog.size >= MAX_CONN) connLog.pollFirst()
        connLog.addLast(e)
        store?.saveConn(e)
        debugCapture?.onConn(e)
        notifyChanged()
    }

    @Synchronized
    fun updateDnsCountry(ip: String?, cc: String?) {
        if (ip.isNullOrEmpty() || cc.isNullOrEmpty()) return
        var changed = false
        for (e in dnsLog) {
            if (ip == e.resolvedIp && cc != e.countryCode) {
                e.countryCode = cc
                changed = true
            }
        }
        store?.updateCountry(ip, cc)
        if (changed) notifyChanged()
    }

    /** Same as updateDnsCountry but for the connection log (dest is "ip:port"). */
    @Synchronized
    fun updateConnCountry(ip: String?, cc: String?) {
        if (ip.isNullOrEmpty() || cc.isNullOrEmpty()) return
        var changed = false
        val prefix = "$ip:"
        for (e in connLog) {
            if (e.dest.startsWith(prefix) && cc != e.countryCode) {
                e.countryCode = cc
                changed = true
            }
        }
        store?.updateCountry(ip, cc)
        if (changed) notifyChanged()
    }

    @Synchronized
    fun dnsSnapshot(): List<Entries.DnsEntry> = ArrayList(dnsLog)

    @Synchronized
    fun connSnapshot(): List<Entries.ConnEntry> = ArrayList(connLog)

    /**
     * Newest-first DNS entries for one app (max items). [filter] uses the
     * DNS Log semantics (0=all 1=blocked 2=allowed 3=bypass) and is applied
     * WHILE collecting — so a busy app's older matching entries are not
     * crowded out by its newest traffic.
     */
    @Synchronized
    fun dnsForApp(app: String, max: Int, filter: Int = 0): List<Entries.DnsEntry> {
        val out = ArrayList<Entries.DnsEntry>()
        val copy = ArrayList(dnsLog)
        var i = copy.size - 1
        while (i >= 0 && out.size < max) {
            val d = copy[i]
            if (d.app == app) {
                val match = when (filter) {
                    1 -> d.blocked
                    2 -> !d.blocked
                    3 -> d.isBypass
                    else -> true
                }
                if (match) out.add(d)
            }
            i--
        }
        return out
    }

    /** Newest-first connections for one app (max items); [filter] 0=all 1=blocked 2=allowed. */
    @Synchronized
    fun connsForApp(app: String, max: Int, filter: Int = 0): List<Entries.ConnEntry> {
        val out = ArrayList<Entries.ConnEntry>()
        val copy = ArrayList(connLog)
        var i = copy.size - 1
        while (i >= 0 && out.size < max) {
            val c = copy[i]
            if (c.app == app) {
                val match = when (filter) {
                    1 -> c.blocked
                    2 -> !c.blocked
                    else -> true
                }
                if (match) out.add(c)
            }
            i--
        }
        return out
    }

    /** Aggregate per-app stats from both logs. Newest apps first. */
    @Synchronized
    fun appStats(): List<Entries.AppStat> {
        val map = HashMap<String, Entries.AppStat>()
        for (d in dnsLog) {
            var s = map[d.app]
            if (s == null) {
                s = Entries.AppStat(d.app)
                map[d.app] = s
            }
            if (s.uid < 0) s.uid = d.uid
            s.queries++
            if (d.blocked) s.blocked++
        }
        for (c in connLog) {
            var s = map[c.app]
            if (s == null) {
                s = Entries.AppStat(c.app)
                map[c.app] = s
            }
            if (s.uid < 0) s.uid = c.uid
            s.conns++
            s.bytesUp += c.bytesUp
            s.bytesDown += c.bytesDown
        }
        val out = ArrayList(map.values)
        out.sortByDescending { it.queries + it.conns }
        return out
    }

    @Synchronized
    fun totals(): LongArray = longArrayOf(totalQueries, totalBlocked)

    /** Register the persistence sink for the all-time counters. */
    fun setTotalsSink(sink: ((Long, Long) -> Unit)?) {
        totalsSink = sink
    }

    /** Set the all-time counters (app start seeding). Does not recount restores. */
    @Synchronized
    fun seedAllTime(q: Long, b: Long) {
        allQueries.set(q)
        allBlocked.set(b)
    }

    fun totalsAll(): LongArray = longArrayOf(allQueries.get(), allBlocked.get())

    /** Persist the all-time counters through the sink (battery-throttled by addDns). */
    @Synchronized
    fun flushTotals() {
        totalsSink?.invoke(allQueries.get(), allBlocked.get())
        addsSinceFlush = 0
    }

    @Synchronized
    fun clear() {
        dnsLog.clear()
        connLog.clear()
        totalQueries = 0
        totalBlocked = 0
        store?.clear()
        notifyChanged()
    }

    fun addListener(l: Listener) {
        listeners.addIfAbsent(l)
    }

    fun removeListener(l: Listener) {
        listeners.remove(l)
    }

    private fun notifyChanged() {
        for (l in listeners) {
            try {
                l.onLogsChanged()
            } catch (_: Exception) {
            }
        }
    }
}
