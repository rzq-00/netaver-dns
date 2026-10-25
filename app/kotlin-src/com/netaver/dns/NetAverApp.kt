package com.netaver.dns

import android.app.Application

import com.netaver.dns.dns.BlocklistManager
import com.netaver.dns.dns.CustomRules
import com.netaver.dns.log.Entries
import com.netaver.dns.log.LogBus
import com.netaver.dns.log.LogStore
import com.netaver.dns.net.GeoIp
import com.netaver.dns.util.AppResolver
import com.netaver.dns.util.DebugCapture
import com.netaver.dns.util.FirewallManager
import com.netaver.dns.util.Prefs

import java.util.ArrayList

/** Holds cross-component singletons (service + UI share these). */
class NetAverApp : Application() {
    private lateinit var prefsInstance: Prefs
    private lateinit var logBusInstance: LogBus
    private lateinit var logStoreInstance: LogStore
    private lateinit var blocklistManagerInstance: BlocklistManager
    private lateinit var appResolverInstance: AppResolver
    private lateinit var firewallInstance: FirewallManager
    private lateinit var geoIpInstance: GeoIp
    private lateinit var customRulesInstance: CustomRules
    private val debugCaptureInstance = DebugCapture()
    private val dnsCacheInstance = com.netaver.dns.dns.DnsCache()

    companion object {
        /** Extract the IP from a "ip:port" dest string. */
        private fun ipFromDest(dest: String?): String {
            if (dest == null) return ""
            val i = dest.lastIndexOf(':')
            return if (i > 0) dest.substring(0, i) else dest
        }
    }

    override fun onCreate() {
        super.onCreate()
        prefsInstance = Prefs(this)
        logBusInstance = LogBus()
        logBusInstance.setDebugCapture(debugCaptureInstance)
        logStoreInstance = LogStore(this)
        logBusInstance.setStore(logStoreInstance)
        logBusInstance.setTotalsSink { q, b -> prefsInstance.setTotalsAll(q, b) }
        blocklistManagerInstance = BlocklistManager(this, prefsInstance)
        appResolverInstance = AppResolver(this)
        firewallInstance = FirewallManager(prefsInstance)
        firewallInstance.setSelfUid(applicationInfo.uid)
        geoIpInstance = GeoIp(this)
        geoIpInstance.setEnabled(prefsInstance.geoipEnabled())
        customRulesInstance = CustomRules()
        customRulesInstance.setText(prefsInstance.customRules())
        dnsCacheInstance.configure(prefsInstance.cacheMinTtlSec(), prefsInstance.cacheOptimistic(), prefsInstance.cacheMaxEntries())
        logBusInstance.setLoggingMode(prefsInstance.loggingMode())
        // Load bundled list off the main thread; custom URLs refresh on VPN start.
        Thread({ blocklistManagerInstance.loadBundled() }, "bl-init").start()
        // Restore persisted logs off the main thread (survive restarts/updates).
        // GeoIp's disk cache is already loaded, so flags come back for free.
        // A1 follow-up: snapshot the clear generation and the process-start
        // time HERE, synchronously in onCreate (main thread, before any UI
        // exists) — a user clear can then never predate the snapshot, and
        // the first-run seed counts only history from BEFORE this process,
        // so rows this process already counted live are never counted twice.
        val genSnapshot = logBusInstance.clearGeneration()
        val procStartMs = System.currentTimeMillis()
        Thread({
            val gen = genSnapshot
            // Seed the all-time Home counters (v2.2.10): first run counts the
            // stored history once; later runs reload the persisted totals.
            // M1: seeding is additive and persists the merged value itself,
            // so nothing here writes the totals twice or clobbers live ones.
            val seeded: Boolean
            if (!prefsInstance.totalsSeeded()) {
                val c = logStoreInstance.countAll(procStartMs)
                seeded = logBusInstance.seedAllTimeIfCurrent(gen, c[0], c[1])
                if (seeded) {
                    prefsInstance.setTotalsSeeded()
                } else {
                    // Gate dropped = a Clear Logs intervened and already
                    // persisted zeroed totals; align the seeded flag so
                    // later starts take the prefs branch, not countAll.
                    prefsInstance.setTotalsAll(0, 0)
                    prefsInstance.setTotalsSeeded()
                }
            } else {
                val t = prefsInstance.totalsAll()
                seeded = logBusInstance.seedAllTimeIfCurrent(gen, t[0], t[1])
            }
            // A clear intervened while seeding: skip the restore entirely.
            if (seeded) {
                val dns = ArrayList<Entries.DnsEntry>()
                val conns = ArrayList<Entries.ConnEntry>()
                logStoreInstance.loadRecent(dns, conns)
                for (d in dns) {
                    if (d.resolvedIp.isNotEmpty() && d.countryCode.isEmpty()) {
                        val cc = geoIpInstance.cached(d.resolvedIp)
                        if (cc.isNotEmpty()) d.countryCode = cc
                    }
                }
                for (c in conns) {
                    if (c.countryCode.isEmpty()) {
                        val cc = geoIpInstance.cached(ipFromDest(c.dest))
                        if (cc.isNotEmpty()) c.countryCode = cc
                    }
                }
                logBusInstance.restoreIfCurrent(gen, dns, conns)
            }
        }, "log-restore").start()
    }

    fun prefs(): Prefs = prefsInstance
    fun logBus(): LogBus = logBusInstance

    fun debugCapture(): DebugCapture = debugCaptureInstance
    fun logStore(): LogStore = logStoreInstance
    fun blocklists(): BlocklistManager = blocklistManagerInstance
    fun resolver(): AppResolver = appResolverInstance
    fun firewall(): FirewallManager = firewallInstance
    fun geoIp(): GeoIp = geoIpInstance
    fun customRules(): CustomRules = customRulesInstance
    fun dnsCache(): com.netaver.dns.dns.DnsCache = dnsCacheInstance

    /** Append a rule (e.g. "||domain^") avoiding duplicates. */
    fun addCustomRule(rule: String) {
        var r = rule.trim()
        if (r.isEmpty()) return
        var cur = prefsInstance.customRules()
        // dedupe: skip if an identical non-comment line already exists
        for (line in cur.split("\n")) {
            if (line.trim() == r) return
        }
        if (cur.isNotEmpty() && !cur.endsWith("\n")) cur += "\n"
        cur += r + "\n"
        prefsInstance.setCustomRules(cur)
        customRulesInstance.setText(cur)
    }
}
