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
        prefs.put("battery_saver", p.batterySaver())
        prefs.put("block_bypass", p.blockBypass())
        prefs.put("bypass_lan", p.bypassLan())
        prefs.put("start_on_boot", p.startOnBoot())
        prefs.put("show_notif", p.showNotif())
        prefs.put("builtin_enabled", p.builtinEnabled())
        prefs.put("firewall_enabled", p.firewallEnabled())
        prefs.put("geoip_enabled", p.geoipEnabled())
        prefs.put("dns_cache", p.dnsCacheEnabled())
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

            val prefs = root.optJSONObject("prefs")
            if (prefs != null) {
                if (prefs.has("upstream")) p.setUpstream(clamp(prefs.optInt("upstream", 0), 0, 3))
                if (prefs.has("dns_protocol")) p.setProtocol(prefs.optInt("dns_protocol", 1))
                if (prefs.has("custom_upstream")) p.setCustomUpstream(prefs.optString("custom_upstream", ""))
                if (prefs.has("fallback_upstream")) p.setFallbackUpstream(prefs.optString("fallback_upstream", "tls://1.1.1.1"))
                if (prefs.has("upstream_list")) {
                    val raw = prefs.optString("upstream_list", "")
                    val list = raw.split(";").map { it.trim() }.filter { it.isNotEmpty() }
                    if (list.isNotEmpty()) p.setUpstreamList(list)
                }
                if (prefs.has("upstream_mode")) p.setUpstreamMode(prefs.optInt("upstream_mode", 0))
                // legacy v1.x backup without upstream_list: rebuild the list from
                // the imported legacy primary+fallback (migration won't re-run
                // because its flag is already set)
                if (!prefs.has("upstream_list")
                    && (prefs.has("upstream") || prefs.has("custom_upstream")
                        || prefs.has("fallback_upstream"))) {
                    p.rebuildUpstreamListFromLegacy()
                }
                if (prefs.has("battery_saver")) p.setBatterySaver(prefs.optBoolean("battery_saver", true))
                if (prefs.has("block_bypass")) p.setBlockBypass(prefs.optBoolean("block_bypass", true))
                if (prefs.has("bypass_lan")) p.setBypassLan(prefs.optBoolean("bypass_lan", true))
                if (prefs.has("start_on_boot")) p.setStartOnBoot(prefs.optBoolean("start_on_boot", false))
                if (prefs.has("show_notif")) p.setShowNotif(prefs.optBoolean("show_notif", true))
                if (prefs.has("builtin_enabled")) p.setBuiltinEnabled(prefs.optBoolean("builtin_enabled", true))
                if (prefs.has("firewall_enabled")) p.setFirewallEnabled(prefs.optBoolean("firewall_enabled", true))
                if (prefs.has("geoip_enabled")) {
                    val v = prefs.optBoolean("geoip_enabled", true)
                    p.setGeoipEnabled(v)
                    app.geoIp().setEnabled(v)
                }
                if (prefs.has("dns_cache")) p.setDnsCacheEnabled(prefs.optBoolean("dns_cache", true))
            }

            val arr = root.optJSONArray("custom_lists")
            if (arr != null) {
                val out = ArrayList<BlocklistManager.CustomList>()
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val url = o.optString("url", "")
                    if (url.isEmpty()) continue
                    out.add(
                        BlocklistManager.CustomList(
                            o.optString("name", url), url, o.optBoolean("enabled", true)
                        )
                    )
                }
                app.blocklists().saveCustomLists(out)
                lists = out.size
            }

            if (root.has("custom_rules")) {
                val rules = root.optString("custom_rules", "")
                p.setCustomRules(rules)
                app.customRules().setText(rules)
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

    private fun clamp(v: Int, lo: Int, hi: Int): Int = maxOf(lo, minOf(hi, v))
}
