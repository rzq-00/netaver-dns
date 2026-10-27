package com.netaver.dns.util

import com.netaver.dns.NetAverApp
import com.netaver.dns.dns.BlocklistManager

import org.json.JSONArray
import org.json.JSONObject

/**
 * Export/import of user settings as JSON (for sharing with friends).
 * Covers: prefs, custom blocklists, custom rules. Firewall rules are
 * intentionally excluded (user request).
 * Uses org.json from the Android framework (no dependencies).
 */
object BackupManager {
    /** Export everything to a JSON string. */
    @JvmStatic
    fun export(app: NetAverApp): String {
        val p = app.prefs()

        val root = JSONObject()
        root.put("app", "netaver-dns")
        root.put("v", 1)

        val prefs = JSONObject()
        prefs.put("upstream", p.getUpstream())
        prefs.put("dns_protocol", p.getProtocol())
        prefs.put("custom_upstream", p.customUpstream())
        prefs.put("fallback_upstream", p.fallbackUpstream())
        prefs.put("upstream_list", p.upstreamList().joinToString(";"))
        prefs.put("upstream_mode", p.upstreamMode())
        prefs.put("custom_upstream_history", p.customUpstreamHistory().joinToString(";"))
        prefs.put("custom_upstream_names", p.customUpstreamNamesRaw())
        prefs.put("battery_saver", p.batterySaver())
        prefs.put("block_bypass", p.blockBypass())
        prefs.put("bypass_lan", p.bypassLan())
        prefs.put("start_on_boot", p.startOnBoot())
        prefs.put("show_notif", p.showNotif())
        prefs.put("builtin_enabled", p.builtinEnabled())
        prefs.put("firewall_enabled", p.firewallEnabled())
        prefs.put("geoip_enabled", p.geoipEnabled())
        prefs.put("dns_cache", p.dnsCacheEnabled())
        prefs.put("split_bypass", p.splitBypassRaw())
        prefs.put("show_system_apps", p.showSystemApps())
        prefs.put("update_auto_check", p.updateAutoCheck())
        prefs.put("cache_min_ttl_sec", p.cacheMinTtlSec())
        prefs.put("cache_optimistic", p.cacheOptimistic())
        prefs.put("advanced_settings", p.advancedSettings())
        prefs.put("cache_max_entries", p.cacheMaxEntries())
        prefs.put("cache_flush_net", p.cacheFlushOnNetworkChange())
        prefs.put("blocklist_check_hours", p.blocklistCheckIntervalHours())
        prefs.put("logging_mode", p.loggingMode())
        prefs.put("log_retention_days", p.logRetentionDays())
        prefs.put("app_language", p.appLanguage())
        // D1: all-time Home totals travel with the backup (restored live).
        // N2: read the LIVE LogBus counters — the persisted Prefs copy
        // lags by up to one flush (50 queries) while the VPN is running.
        val totals = app.logBus().totalsAll()
        prefs.put("total_queries_all", totals[0])
        prefs.put("total_blocked_all", totals[1])
        root.put("prefs", prefs)

        val lists = JSONArray()
        for (cl in app.blocklists().customLists()) {
            val o = JSONObject()
            o.put("name", cl.name)
            o.put("url", cl.url)
            o.put("enabled", cl.enabled)
            lists.put(o)
        }
        root.put("custom_lists", lists)
        root.put("custom_rules", p.customRules())
        // NOTE: firewall rules are intentionally NOT exported (user request).
        return root.toString(2)
    }

    /**
     * Import settings from JSON. Returns a human-readable summary,
     * or an error message starting with "Error: ".
     */
    @JvmStatic
    fun importJson(app: NetAverApp, json: String): String {
        try {
            val root = JSONObject(json)
            if ("netaver-dns" != root.optString("app")) {
                return "Error: not a NetAver DNS backup file"
            }
            val p = app.prefs()
            var lists = 0

            // D2: VALIDATE FIRST, typed reads only — a key whose JSON value
            // has the wrong type is SKIPPED, never degraded to a default
            // that would overwrite the user's current value. Only after
            // everything has parsed does the apply phase call setters; a
            // throw anywhere above leaves every setting untouched.
            val prefs = root.optJSONObject("prefs")
            val bools = HashMap<String, Boolean>()
            val ints = HashMap<String, Int>()
            val strs = HashMap<String, String>()
            var importedTotals: LongArray? = null
            if (prefs != null) {
                for (k in BOOL_KEYS) jBool(prefs, k)?.let { bools[k] = it }
                for (k in INT_KEYS) jInt(prefs, k)?.let { ints[k] = it }
                for (k in STR_KEYS) jStr(prefs, k)?.let { strs[k] = it }
                val tq = jLong(prefs, "total_queries_all")
                val tb = jLong(prefs, "total_blocked_all")
                // N1: sanity-clamp imported totals — a hand-edited or
                // corrupt backup must not install negative counters or
                // blocked > queries (Home would show a negative or
                // >100% block rate until real traffic outgrew them).
                if (tq != null && tb != null) {
                    val q = maxOf(0L, tq)
                    importedTotals = longArrayOf(q, tb.coerceIn(0L, q))
                }
            }

            // custom lists parsed now, applied later (D2c: the stored format
            // is ';'-joined name|url|enabled entries, so a URL containing
            // ';', '|' or whitespace would corrupt it — drop those entries,
            // like empty ones)
            var parsedLists: ArrayList<BlocklistManager.CustomList>? = null
            val arr = root.optJSONArray("custom_lists")
            if (arr != null) {
                val out = ArrayList<BlocklistManager.CustomList>()
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val url = o.optString("url", "")
                    if (url.isEmpty()) continue
                    if (url.contains(';') || url.contains('|') || url.any { it.isWhitespace() }) continue
                    out.add(
                        BlocklistManager.CustomList(
                            o.optString("name", url), url, o.optBoolean("enabled", true)
                        )
                    )
                }
                parsedLists = out
            }
            val parsedRules = jStr(root, "custom_rules")

            // ---- apply phase: no parsing or validation below this line ----
            if (prefs != null) {
                ints["upstream"]?.let { p.setUpstream(clamp(it, 0, 3)) }
                ints["dns_protocol"]?.let { p.setProtocol(it) }
                strs["custom_upstream"]?.let { p.setCustomUpstream(it) }
                strs["fallback_upstream"]?.let { p.setFallbackUpstream(it) }
                strs["upstream_list"]?.let { raw ->
                    val list = raw.split(";").map { it.trim() }.filter { it.isNotEmpty() }
                    if (list.isNotEmpty()) p.setUpstreamList(list)
                }
                // History + names travel with the backup. Same guard as
                // upstream_list: an empty backup value never wipes the
                // current data. History entries are filtered to the explicit
                // DoT/DoH custom format, same rule as rememberCustom.
                strs["custom_upstream_history"]?.let { raw ->
                    val list = raw.split(";").map { it.trim() }.filter { it.isNotEmpty() }
                        .filter { val l = it.lowercase(); l.startsWith("tls://") || l.startsWith("https://") }
                    if (list.isNotEmpty()) p.setCustomUpstreamHistory(list)
                }
                strs["custom_upstream_names"]?.let { raw ->
                    val m = LinkedHashMap<String, String>()
                    for (e in raw.split(";")) {
                        val i = e.indexOf('\u0001')
                        if (i > 0) {
                            val n = e.substring(i + 1)
                            if (n.isNotEmpty()) m[e.substring(0, i)] = n
                        }
                    }
                    if (m.isNotEmpty()) p.setCustomUpstreamNames(m)
                }
                ints["upstream_mode"]?.let { p.setUpstreamMode(it) }
                // legacy v1.x backup without upstream_list: rebuild the list from
                // the imported legacy primary+fallback (migration won't re-run
                // because its flag is already set)
                if (!strs.containsKey("upstream_list")
                    && (ints.containsKey("upstream") || strs.containsKey("custom_upstream")
                        || strs.containsKey("fallback_upstream"))) {
                    p.rebuildUpstreamListFromLegacy()
                }
                bools["battery_saver"]?.let { p.setBatterySaver(it) }
                bools["block_bypass"]?.let { p.setBlockBypass(it) }
                bools["bypass_lan"]?.let { p.setBypassLan(it) }
                bools["start_on_boot"]?.let { p.setStartOnBoot(it) }
                bools["show_notif"]?.let { p.setShowNotif(it) }
                bools["builtin_enabled"]?.let { p.setBuiltinEnabled(it) }
                bools["firewall_enabled"]?.let { p.setFirewallEnabled(it) }
                bools["geoip_enabled"]?.let { v ->
                    p.setGeoipEnabled(v)
                    app.geoIp().setEnabled(v)
                }
                bools["dns_cache"]?.let { p.setDnsCacheEnabled(it) }
                strs["split_bypass"]?.let { p.setSplitBypassRaw(it) }
                bools["show_system_apps"]?.let { p.setShowSystemApps(it) }
                bools["update_auto_check"]?.let { p.setUpdateAutoCheck(it) }
                ints["cache_min_ttl_sec"]?.let { p.setCacheMinTtlSec(it) }
                bools["cache_optimistic"]?.let { p.setCacheOptimistic(it) }
                bools["advanced_settings"]?.let { p.setAdvancedSettings(it) }
                ints["cache_max_entries"]?.let { p.setCacheMaxEntries(it) }
                bools["cache_flush_net"]?.let { p.setCacheFlushOnNetworkChange(it) }
                ints["blocklist_check_hours"]?.let { p.setBlocklistCheckIntervalHours(it) }
                ints["logging_mode"]?.let { p.setLoggingMode(it) }
                ints["log_retention_days"]?.let { p.setLogRetentionDays(it) }
                strs["app_language"]?.let { p.setAppLanguage(it) }
                // D1: imported all-time totals replace the live counters
                importedTotals?.let {
                    app.logBus().overrideAllTime(it[0], it[1])
                    p.setTotalsSeeded()
                }
                // apply the imported cache policy right away
                app.dnsCache().configure(p.cacheMinTtlSec(), p.cacheOptimistic(), p.cacheMaxEntries())
                app.dnsCache().clear()
                app.logBus().setLoggingMode(p.loggingMode())
            }

            parsedLists?.let {
                app.blocklists().saveCustomLists(it)
                lists = it.size
            }

            parsedRules?.let {
                p.setCustomRules(it)
                app.customRules().setText(it)
            }

            // NOTE: firewall rules are intentionally NOT imported (user request).

            // refresh blocklists in background so imported lists take effect
            if (lists > 0) {
                Thread({
                    try {
                        app.blocklists().refreshCustomLists()
                    } catch (_: Exception) {
                    }
                }, "bl-import").start()
            }

            val sb = StringBuilder("Settings imported")
            if (lists > 0) sb.append(" · ").append(lists).append(" lists (updating…)")
            return sb.toString()
        } catch (e: Exception) {
            return "Error: invalid backup file (" + e.message + ")"
        }
    }

    // D2: typed reads — non-null ONLY when the key is present AND its JSON
    // value has exactly the expected type (org.json's opt* getters would
    // otherwise coerce e.g. the string "false" into a plausible value).
    private fun jBool(o: JSONObject, key: String): Boolean? {
        if (!o.has(key)) return null
        val v = o.get(key)
        return if (v is Boolean) v else null
    }

    private fun jInt(o: JSONObject, key: String): Int? {
        if (!o.has(key)) return null
        val v = o.get(key)
        return if (v is Number) v.toInt() else null
    }

    private fun jLong(o: JSONObject, key: String): Long? {
        if (!o.has(key)) return null
        val v = o.get(key)
        return if (v is Number) v.toLong() else null
    }

    private fun jStr(o: JSONObject, key: String): String? {
        if (!o.has(key)) return null
        val v = o.get(key)
        return if (v is String) v else null
    }

    private val BOOL_KEYS = arrayOf(
        "battery_saver", "block_bypass", "bypass_lan", "start_on_boot",
        "show_notif", "builtin_enabled", "firewall_enabled", "geoip_enabled",
        "dns_cache", "show_system_apps", "update_auto_check",
        "cache_optimistic", "advanced_settings", "cache_flush_net")

    private val INT_KEYS = arrayOf(
        "upstream", "dns_protocol", "upstream_mode", "cache_min_ttl_sec",
        "cache_max_entries", "blocklist_check_hours", "logging_mode",
        "log_retention_days")

    private val STR_KEYS = arrayOf(
        "custom_upstream", "fallback_upstream", "upstream_list",
        "custom_upstream_history", "custom_upstream_names",
        "split_bypass", "app_language")

    private fun clamp(v: Int, lo: Int, hi: Int): Int = maxOf(lo, minOf(hi, v))
}
