package com.netaver.dns.util

import android.content.Context
import android.content.SharedPreferences

import com.netaver.dns.R

/** Simple typed preferences. */
class Prefs(ctx: Context) {
    private val sp: SharedPreferences =
        ctx.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    /** Parsed custom upstream. protoOverride -1 = use protocol radio. */
    class CustomSpec {
        @JvmField var protoOverride: Int = -1 // 0=DNS 1=DoT 2=DoH, -1 = follow radio
        @JvmField var host: String = ""       // IP or hostname (no scheme)
        @JvmField var port: Int = -1          // -1 = default per proto
        @JvmField var path: String = "/dns-query"
        @JvmField var valid: Boolean = false
    }

    companion object {
        private const val NAME = "sunraku_dns"

        const val KEY_UPSTREAM = "upstream" // 0=cloudflare 1=google 2=quad9 3=custom
        const val KEY_PROTOCOL = "dns_protocol" // 0=plain DNS 1=DoT 2=DoH
        const val KEY_CUSTOM_UPSTREAM = "custom_upstream" // tls://host, https://host/path, IP, hostname
        const val KEY_FALLBACK_UPSTREAM = "fallback_upstream" // same format; used when primary fails
        // Multi-upstream (AdGuard Home style)
        const val KEY_UPSTREAM_LIST = "upstream_list" // ";"-separated specs: "preset:0" or free-form
        const val KEY_UPSTREAM_MODE = "upstream_mode" // 0=parallel 1=fastest 2=sequential
        const val KEY_UPSTREAMS_MIGRATED = "upstreams_migrated"
        const val MAX_UPSTREAMS = 5 // battery guard: bound parallel fan-out
        const val MODE_PARALLEL = 0
        const val MODE_FASTEST = 1
        const val MODE_SEQUENTIAL = 2
        const val KEY_BATTERY_SAVER = "battery_saver"
        const val KEY_BLOCK_BYPASS = "block_bypass"
        const val KEY_BYPASS_LAN = "bypass_lan"
        const val KEY_START_ON_BOOT = "start_on_boot"
        const val KEY_SHOW_NOTIF = "show_notif"
        const val KEY_CUSTOM_LISTS = "custom_lists" // name|url|enabled;...
        const val KEY_BUILTIN_ENABLED = "builtin_enabled"
        const val KEY_LAST_LIST_UPDATE = "last_list_update"
        const val KEY_LAST_LIST_CHECK = "last_list_check"
        const val KEY_LAST_LIST_STATUS = "last_list_status"
        const val KEY_LAST_LIST_STATUS_JSON = "last_list_status_json"
        const val KEY_FIREWALL_ENABLED = "firewall_enabled"
        const val KEY_FIREWALL_RULES = "firewall_rules" // uid:rule;...
        const val KEY_GEOIP_ENABLED = "geoip_enabled"
        const val KEY_DNS_CACHE = "dns_cache"
        const val KEY_CUSTOM_RULES = "custom_rules"
        const val KEY_SPLIT_BYPASS = "split_bypass" // pkg;pkg;... (bypass VPN entirely)
        const val KEY_TOTAL_QUERIES_ALL = "total_queries_all" // cumulative Home counter
        const val KEY_TOTAL_BLOCKED_ALL = "total_blocked_all" // cumulative Home counter
        const val KEY_TOTALS_SEEDED = "totals_seeded"
        const val KEY_SHOW_SYSTEM_APPS = "show_system_apps"

        // Built-in default custom lists (Hagezi) - user can toggle
        const val DEFAULT_HAGEZI_PRO =
            "Hagezi Pro|https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.txt|0"
        const val DEFAULT_HAGEZI_MULTIPRO =
            "Hagezi Multi PRO|https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus.txt|0"

        /** Parse tls://host, https://host/path, bare IP or hostname. Pure, no I/O. */
        @JvmStatic
        fun parseCustomUpstream(raw: String?): CustomSpec {
            val s = CustomSpec()
            if (raw == null) return s
            var r = raw.trim()
            if (r.isEmpty()) return s
            try {
                val low = r.lowercase()
                if (low.startsWith("https://")) {
                    s.protoOverride = 2
                    val rest = r.substring(8)
                    val slash = rest.indexOf('/')
                    val hostPort = if (slash < 0) rest else rest.substring(0, slash)
                    s.path = if (slash < 0) "/dns-query" else rest.substring(slash)
                    if (s.path.isEmpty()) s.path = "/dns-query"
                    parseHostPort(hostPort, s, 443)
                } else if (low.startsWith("tls://")) {
                    s.protoOverride = 1
                    parseHostPort(r.substring(6), s, 853)
                } else {
                    // bare IP or hostname, maybe with :port
                    parseHostPort(r, s, -1)
                }
            } catch (_: Exception) {
                return s
            }
            s.valid = s.host.isNotEmpty() && isValidHost(s.host)
            return s
        }

        private fun parseHostPort(hp: String, s: CustomSpec, defaultPort: Int) {
            var h = hp.trim()
            // strip trailing path if any leaked in
            val slash = h.indexOf('/')
            if (slash >= 0) h = h.substring(0, slash)
            // [::1]:port or host:port (single colon + digits)
            val colon = h.lastIndexOf(':')
            if (colon > 0 && h.indexOf(':') == colon && h.substring(colon + 1).matches("\\d+".toRegex())) {
                try {
                    val port = h.substring(colon + 1).toInt()
                    // reject out-of-range ports (e.g. 99999) instead of failing at connect
                    if (port in 1..65535) {
                        s.port = port
                        h = h.substring(0, colon)
                    }
                } catch (_: NumberFormatException) {
                }
            }
            if (s.port <= 0) s.port = defaultPort
            s.host = h.trim()
        }

        @JvmStatic
        fun isValidHost(h: String?): Boolean {
            if (h == null || h.isEmpty() || h.length > 253) return false
            if (isValidIpv4(h)) return true
            // hostname: labels of alnum/hyphen separated by dots
            if (!h.contains(".")) return false
            // Java's String.split drops trailing empty strings; mirror that.
            for (label in h.split(".").dropLastWhile { it.isEmpty() }) {
                if (label.isEmpty() || label.length > 63) return false
                if (label.startsWith("-") || label.endsWith("-")) return false
                for (c in label) {
                    if (c !in 'a'..'z' && c !in 'A'..'Z'
                        && c !in '0'..'9' && c != '-'
                    ) return false
                }
            }
            return true
        }

        @JvmStatic
        fun isValidIpv4(ip: String?): Boolean {
            if (ip == null) return false
            // Java's String.split drops trailing empty strings; mirror that.
            val p = ip.split(".").dropLastWhile { it.isEmpty() }
            if (p.size != 4) return false
            for (s in p) {
                try {
                    val v = s.toInt()
                    if (v < 0 || v > 255) return false
                } catch (_: NumberFormatException) {
                    return false
                }
            }
            return true
        }

        /** Upstream DNS IP for the selected provider. */
        @JvmStatic
        fun upstreamIp(which: Int): String {
            return when (which) {
                1 -> "8.8.8.8"
                2 -> "9.9.9.9"
                else -> "1.1.1.1"
            }
        }

        @JvmStatic
        fun modeNameRes(mode: Int): Int = when (mode) {
            MODE_FASTEST -> R.string.mode_fastest
            MODE_SEQUENTIAL -> R.string.mode_sequential
            else -> R.string.mode_parallel
        }

        fun upstreamName(which: Int): String {
            return when (which) {
                1 -> "Google"
                2 -> "Quad9"
                else -> "Cloudflare"
            }
        }

        @JvmStatic
        fun protoName(p: Int): String {
            return when (p) {
                1 -> "DoT"
                2 -> "DoH"
                else -> "DNS"
            }
        }

        /** TLS hostname for DoT/DoH (SNI + cert verification). */
        @JvmStatic
        fun upstreamTlsHost(which: Int): String {
            return when (which) {
                1 -> "dns.google"
                2 -> "dns.quad9.net"
                else -> "one.one.one.one"
            }
        }
    }

    fun getUpstream(): Int = sp.getInt(KEY_UPSTREAM, 0)
    fun setUpstream(v: Int) {
        sp.edit().putInt(KEY_UPSTREAM, v).apply()
    }

    fun getProtocol(): Int {
        val v = sp.getInt(KEY_PROTOCOL, 1) // default DoT; plain DNS removed in v1.4
        return if (v == 2) 2 else 1 // coerce legacy plain-DNS (0) to DoT
    }

    fun setProtocol(v: Int) {
        sp.edit().putInt(KEY_PROTOCOL, if (v == 2) 2 else 1).apply()
    }

    fun customUpstream(): String {
        val v: String = sp.getString(KEY_CUSTOM_UPSTREAM, "") ?: ""
        if (v.isNotEmpty()) return v
        // migrate from v1.2 two-field format
        return sp.getString("custom_upstream_ip", "") ?: ""
    }

    fun setCustomUpstream(v: String) {
        sp.edit().putString(KEY_CUSTOM_UPSTREAM, v).apply()
    }

    /** Fallback DNS (same format as custom upstream). Used when primary fails 3x. */
    fun fallbackUpstream(): String =
        sp.getString(KEY_FALLBACK_UPSTREAM, "tls://1.1.1.1") ?: "tls://1.1.1.1"

    fun setFallbackUpstream(v: String) {
        sp.edit().putString(KEY_FALLBACK_UPSTREAM, v).apply()
    }

    // ---------------- multi-upstream (AdGuard Home style) ----------------

    /** Ordered upstream specs. Each: "preset:0|1|2" or free-form (tls://, https://, IP, hostname). */
    fun upstreamList(): List<String> {
        val raw: String = sp.getString(KEY_UPSTREAM_LIST, "") ?: ""
        if (raw.isEmpty()) return emptyList()
        return raw.split(";").map { it.trim() }.filter { it.isNotEmpty() }.take(MAX_UPSTREAMS)
    }

    fun setUpstreamList(v: List<String>) {
        val clean = v.map { it.trim() }.filter { it.isNotEmpty() }.distinct().take(MAX_UPSTREAMS)
        sp.edit().putString(KEY_UPSTREAM_LIST, clean.joinToString(";")).apply()
    }

    /** 0=parallel (race, fastest wins), 1=fastest (lowest latency EMA), 2=sequential (ordered failover). */
    fun upstreamMode(): Int = sp.getInt(KEY_UPSTREAM_MODE, MODE_PARALLEL)

    fun setUpstreamMode(m: Int) {
        sp.edit().putInt(KEY_UPSTREAM_MODE, m.coerceIn(0, 2)).apply()
    }

    /** String resource for the current mode name (localized display). */
    fun modeNameRes(): Int = modeNameRes(upstreamMode())

    fun upstreamModeName(): String = when (upstreamMode()) {
        MODE_FASTEST -> "Tercepat"
        MODE_SEQUENTIAL -> "Berurutan"
        else -> "Paralel"
    }

    /**
     * One-time migration: legacy single primary (+fallback) -> upstream list.
     * Safe to call on every VPN start; no-op after the first run.
     */
    fun migrateUpstreamsIfNeeded() {
        if (sp.getBoolean(KEY_UPSTREAMS_MIGRATED, false)) return
        val list = ArrayList<String>()
        val which = getUpstream()
        val primarySpec = if (which == 3) {
            val c = customUpstream().trim()
            if (c.isEmpty()) "preset:0" else c
        } else "preset:$which"
        list.add(primarySpec)
        val fb = fallbackUpstream().trim()
        // skip fallback if identical spec OR same server (e.g. preset:0 + tls://1.1.1.1)
        if (fb.isNotEmpty() && !list.contains(fb) && !sameServer(primarySpec, fb)) list.add(fb)
        sp.edit()
            .putString(KEY_UPSTREAM_LIST, list.distinct().take(MAX_UPSTREAMS).joinToString(";"))
            .putInt(KEY_UPSTREAM_MODE, MODE_PARALLEL)
            .putBoolean(KEY_UPSTREAMS_MIGRATED, true)
            .apply()
    }

    /** Rebuild upstream_list from legacy primary+fallback (v1.x backup import). */
    fun rebuildUpstreamListFromLegacy() {
        val which = getUpstream()
        val primarySpec = if (which == 3) {
            val c = customUpstream().trim()
            if (c.isEmpty()) "preset:0" else c
        } else "preset:$which"
        val list = ArrayList<String>()
        list.add(primarySpec)
        val fb = fallbackUpstream().trim()
        if (fb.isNotEmpty() && !list.contains(fb) && !sameServer(primarySpec, fb)) list.add(fb)
        setUpstreamList(list.distinct().take(MAX_UPSTREAMS))
    }

    /** Host/IP of a spec for dedupe ("preset:N" -> known IP, else parsed host). */
    private fun specHostOf(spec: String): String? {
        if (spec.startsWith("preset:")) {
            val w = spec.removePrefix("preset:").toIntOrNull() ?: return null
            return upstreamIp(w)
        }
        val s = parseCustomUpstream(spec)
        return if (s.valid) s.host.lowercase() else null
    }

    private fun sameServer(a: String, b: String): Boolean {
        val ha = specHostOf(a) ?: return false
        val hb = specHostOf(b) ?: return false
        return ha == hb
    }

    /** Localized upstream summary for UI (no I/O): "3 upstream · Fastest". */
    fun upstreamLabel(ctx: Context): String {
        val w = Lang.wrap(ctx)
        val n = upstreamList().size.coerceAtLeast(1)
        return w.getString(R.string.upstream_stat_fmt, n, w.getString(modeNameRes(upstreamMode())))
    }

    fun batterySaver(): Boolean = sp.getBoolean(KEY_BATTERY_SAVER, true)
    fun setBatterySaver(v: Boolean) {
        sp.edit().putBoolean(KEY_BATTERY_SAVER, v).apply()
    }

    fun blockBypass(): Boolean = sp.getBoolean(KEY_BLOCK_BYPASS, true)
    fun setBlockBypass(v: Boolean) {
        sp.edit().putBoolean(KEY_BLOCK_BYPASS, v).apply()
    }

    /** LAN passthrough: RFC1918/link-local traffic skips filter, firewall and logs. */
    fun bypassLan(): Boolean = sp.getBoolean(KEY_BYPASS_LAN, true)
    fun setBypassLan(v: Boolean) {
        sp.edit().putBoolean(KEY_BYPASS_LAN, v).apply()
    }

    fun logsCollapsed(): Boolean = sp.getBoolean("logs_collapsed", false)
    fun setLogsCollapsed(v: Boolean) {
        sp.edit().putBoolean("logs_collapsed", v).apply()
    }

/** Per-app language override: "" = follow system, "en", "in". */
    fun appLanguage(): String = sp.getString("app_language", "") ?: ""

    // ---- in-app updates (GitHub Releases) ----
    fun updateAutoCheck(): Boolean = sp.getBoolean("update_auto_check", true)
    fun setUpdateAutoCheck(v: Boolean) {
        sp.edit().putBoolean("update_auto_check", v).apply()
    }

    fun lastUpdateCheck(): Long = sp.getLong("update_last_check", 0L)
    fun setLastUpdateCheck(v: Long) {
        sp.edit().putLong("update_last_check", v).apply()
    }

    /** Tag (e.g. "v2.3.2") of the newest release known to be newer than installed, "" = none. */
    fun updateAvailable(): String = sp.getString("update_available", "") ?: ""
    fun setUpdateAvailable(v: String) {
        sp.edit().putString("update_available", v).apply()
    }

    /** Tag we already popped the update dialog for (auto-check prompts once per version). */
    fun updatePromptedTag(): String = sp.getString("update_prompted_tag", "") ?: ""
    fun setUpdatePromptedTag(v: String) {
        sp.edit().putString("update_prompted_tag", v).apply()
    }

    fun cachedReleasesJson(): String = sp.getString("update_releases_cache", "") ?: ""
    fun setCachedReleasesJson(v: String) {
        sp.edit().putString("update_releases_cache", v).apply()
    }
    fun setAppLanguage(v: String) {
        sp.edit().putString("app_language", v).apply()
    }

    fun backupCollapsed(): Boolean = sp.getBoolean("backup_collapsed", false)
    fun setBackupCollapsed(v: Boolean) {
        sp.edit().putBoolean("backup_collapsed", v).apply()
    }


    fun startOnBoot(): Boolean = sp.getBoolean(KEY_START_ON_BOOT, false)
    fun setStartOnBoot(v: Boolean) {
        sp.edit().putBoolean(KEY_START_ON_BOOT, v).apply()
    }

    fun showNotif(): Boolean = sp.getBoolean(KEY_SHOW_NOTIF, true)
    fun setShowNotif(v: Boolean) {
        sp.edit().putBoolean(KEY_SHOW_NOTIF, v).apply()
    }

    fun firewallEnabled(): Boolean = sp.getBoolean(KEY_FIREWALL_ENABLED, true)
    fun setFirewallEnabled(v: Boolean) {
        sp.edit().putBoolean(KEY_FIREWALL_ENABLED, v).apply()
    }

    fun geoipEnabled(): Boolean = sp.getBoolean(KEY_GEOIP_ENABLED, true)
    fun setGeoipEnabled(v: Boolean) {
        sp.edit().putBoolean(KEY_GEOIP_ENABLED, v).apply()
    }

    fun dnsCacheEnabled(): Boolean = sp.getBoolean(KEY_DNS_CACHE, true)
    fun setDnsCacheEnabled(v: Boolean) {
        sp.edit().putBoolean(KEY_DNS_CACHE, v).apply()
    }

    fun firewallRulesRaw(): String = sp.getString(KEY_FIREWALL_RULES, "") ?: ""
    fun setFirewallRulesRaw(raw: String) {
        sp.edit().putString(KEY_FIREWALL_RULES, raw).apply()
    }

    fun customRules(): String = sp.getString(KEY_CUSTOM_RULES, "") ?: ""
    fun setCustomRules(text: String) {
        sp.edit().putString(KEY_CUSTOM_RULES, text).apply()
    }

    /** Packages that bypass the VPN entirely (split tunnel), ";"-separated. */
    fun splitBypassRaw(): String = sp.getString(KEY_SPLIT_BYPASS, "") ?: ""
    fun setSplitBypassRaw(raw: String) {
        sp.edit().putString(KEY_SPLIT_BYPASS, raw).apply()
    }

    /** Cumulative Home counters (all-time totals, survive restarts). */
    fun totalsAll(): LongArray = longArrayOf(
        sp.getLong(KEY_TOTAL_QUERIES_ALL, 0L),
        sp.getLong(KEY_TOTAL_BLOCKED_ALL, 0L))

    fun setTotalsAll(q: Long, b: Long) {
        sp.edit().putLong(KEY_TOTAL_QUERIES_ALL, q)
            .putLong(KEY_TOTAL_BLOCKED_ALL, b).apply()
    }

    fun totalsSeeded(): Boolean = sp.getBoolean(KEY_TOTALS_SEEDED, false)

    /** Show system apps in app lists (Split Tunnel + Apps tab). Default off. */
    fun showSystemApps(): Boolean = sp.getBoolean(KEY_SHOW_SYSTEM_APPS, false)

    fun setShowSystemApps(on: Boolean) {
        sp.edit().putBoolean(KEY_SHOW_SYSTEM_APPS, on).apply()
    }

    fun setTotalsSeeded() {
        sp.edit().putBoolean(KEY_TOTALS_SEEDED, true).apply()
    }

    fun splitBypassSet(): Set<String> {
        val out = HashSet<String>()
        for (p in splitBypassRaw().split(";")) {
            val t = p.trim()
            if (t.isNotEmpty()) out.add(t)
        }
        return out
    }

    fun setSplitBypassSet(pkgs: Set<String>) {
        val sb = StringBuilder()
        for (p in pkgs) {
            if (sb.isNotEmpty()) sb.append(';')
            sb.append(p)
        }
        setSplitBypassRaw(sb.toString())
    }

    fun builtinEnabled(): Boolean = sp.getBoolean(KEY_BUILTIN_ENABLED, true)
    fun setBuiltinEnabled(v: Boolean) {
        sp.edit().putBoolean(KEY_BUILTIN_ENABLED, v).apply()
    }

    fun lastListUpdate(): Long = sp.getLong(KEY_LAST_LIST_UPDATE, 0)
    fun setLastListUpdate(v: Long) {
        sp.edit().putLong(KEY_LAST_LIST_UPDATE, v).apply()
    }

    /** Last conditional-check attempt (any outcome) + its display status. */
    fun lastListCheck(): Long = sp.getLong(KEY_LAST_LIST_CHECK, 0)
    fun setLastListCheck(v: Long) {
        sp.edit().putLong(KEY_LAST_LIST_CHECK, v).apply()
    }

    fun lastListStatus(): String = sp.getString(KEY_LAST_LIST_STATUS, "") ?: ""
    fun setLastListStatus(v: String) {
        sp.edit().putString(KEY_LAST_LIST_STATUS, v).apply()
    }

    /** Raw JSON outcome of the last list refresh (counts + timestamp). */
    fun lastListStatusJson(): String = sp.getString(KEY_LAST_LIST_STATUS_JSON, "") ?: ""
    fun setLastListStatusJson(v: String) {
        sp.edit().putString(KEY_LAST_LIST_STATUS_JSON, v).apply()
    }

    fun customListsRaw(): String {
        var raw: String? = sp.getString(KEY_CUSTOM_LISTS, null)
        if (raw == null) {
            raw = "$DEFAULT_HAGEZI_PRO;$DEFAULT_HAGEZI_MULTIPRO"
            sp.edit().putString(KEY_CUSTOM_LISTS, raw).apply()
        }
        return raw
    }

    fun setCustomListsRaw(raw: String) {
        sp.edit().putString(KEY_CUSTOM_LISTS, raw).apply()
    }
}
