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

    /** Logging mode (advanced setting): 0 full, 1 DNS only, 2 minimal. */
    @Volatile
    var loggingMode: Int = 0
        private set

    fun setLoggingMode(m: Int) {
        loggingMode = m.coerceIn(0, 2)
    }

    private var totalQueries = 0L
    private var totalBlocked = 0L

    // All-time cumulative counters for Home (v2.2.10): seeded at app start
    // (first run from stored history, later from Prefs), incremented per
    // query, flushed to Prefs via the sink every 50 queries and on demand.
    private val allQueries = java.util.concurrent.atomic.AtomicLong(0)
    private val allBlocked = java.util.concurrent.atomic.AtomicLong(0)
    private var totalsSink: ((Long, Long) -> Unit)? = null
    private var addsSinceFlush = 0
    // M1: while false, flushTotals() must NOT write — the in-memory counters
    // don't include the persisted lifetime totals yet, and persisting them
    // would destroy those totals before the app-start seed merges them.
    @Volatile private var totalsSeeded = false
    // A1: bumped by every clear(). The restore thread snapshots it and its
    // seed/restore are dropped when a clear intervened meanwhile.
    @Volatile private var clearGeneration = 0L

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
        // D4: restored rows only refill the rings — they must NOT feed the
        // per-process session counters (totals() has no UI consumer; Home
        // shows the all-time counters, which are seeded separately).
        for (e in dns) {
            if (dnsLog.size >= MAX_DNS) dnsLog.pollFirst()
            dnsLog.addLast(e)
        }
        for (e in conns) {
            if (connLog.size >= MAX_CONN) connLog.pollFirst()
            connLog.addLast(e)
        }
        notifyChanged()
    }

    /**
     * A1: [restore] gated on the clear generation — returns false and does
     * nothing when a clear() happened since [gen] was captured, so a late
     * app-start restore never resurrects logs the user just cleared.
     */
    @Synchronized
    fun restoreIfCurrent(gen: Long, dns: List<Entries.DnsEntry>, conns: List<Entries.ConnEntry>): Boolean {
        if (gen != clearGeneration) return false
        restore(dns, conns)
        return true
    }

    @Synchronized
    fun addDns(e: Entries.DnsEntry) {
        // Counters ALWAYS count (Home totals must stay truthful);
        // the logging mode only gates what gets recorded.
        totalQueries++
        if (e.blocked) totalBlocked++
        allQueries.incrementAndGet()
        if (e.blocked) allBlocked.incrementAndGet()
        if (++addsSinceFlush >= 50) flushTotals()
        debugCapture?.onDns(e) // an active debug capture always sees everything
        if (loggingMode == 2 && !e.blocked) return // minimal: blocked only
        if (dnsLog.size >= MAX_DNS) dnsLog.pollFirst()
        dnsLog.addLast(e)
        store?.saveDns(e)
        notifyChanged()
    }

    @Synchronized
    fun addConn(e: Entries.ConnEntry) {
        debugCapture?.onConn(e)
        if (loggingMode >= 1) return // DNS only / minimal: no connection log
        if (connLog.size >= MAX_CONN) connLog.pollFirst()
        connLog.addLast(e)
        store?.saveConn(e)
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
                    2 -> !d.blocked && !d.isBypass
                    3 -> d.isBypass
                    4 -> d.fromCache
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

    /** Current clear generation (A1): snapshot before async restore work. */
    @Synchronized
    fun clearGeneration(): Long = clearGeneration

    /**
     * Seed the all-time counters (app start). M1: ADDITIVE and one-shot —
     * queries already counted live are kept, the persisted totals are merged
     * in, and the merged value is persisted at once. A late or repeated seed
     * can no longer overwrite the live counters.
     */
    @Synchronized
    fun seedAllTime(q: Long, b: Long) {
        if (totalsSeeded) return
        allQueries.addAndGet(q)
        allBlocked.addAndGet(b)
        totalsSeeded = true
        flushTotals()
    }

    /**
     * A1: [seedAllTime] gated on the clear generation — returns false and
     * does nothing when a clear() happened since [gen] was captured.
     */
    @Synchronized
    fun seedAllTimeIfCurrent(gen: Long, q: Long, b: Long): Boolean {
        if (gen != clearGeneration) return false
        seedAllTime(q, b)
        return true
    }

    /**
     * D1: replace the all-time counters with imported totals (backup
     * restore). Marks them seeded so they persist at once via the sink and
     * the app-start seed never overwrites them.
     */
    @Synchronized
    fun overrideAllTime(q: Long, b: Long) {
        allQueries.set(q)
        allBlocked.set(b)
        totalsSeeded = true
        flushTotals()
    }

    fun totalsAll(): LongArray = longArrayOf(allQueries.get(), allBlocked.get())

    /** Persist the all-time counters through the sink (battery-throttled by addDns). */
    @Synchronized
    fun flushTotals() {
        // M1: before seeding, the stored lifetime totals must survive —
        // the in-memory counters don't include them yet.
        if (!totalsSeeded) return
        totalsSink?.invoke(allQueries.get(), allBlocked.get())
        addsSinceFlush = 0
    }

    @Synchronized
    fun clear() {
        clearGeneration++ // A1: invalidate any in-flight app-start restore
        dnsLog.clear()
        connLog.clear()
        totalQueries = 0
        totalBlocked = 0
        // Clear Logs also resets the statistics (his order 2026-10-23):
        // the all-time Home totals go back to 0 and are persisted at once.
        allQueries.set(0)
        allBlocked.set(0)
        totalsSeeded = true // M1: unblock flushTotals so the zeros persist
        flushTotals()
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
