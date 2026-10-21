package com.netaver.dns.util

import java.util.concurrent.ConcurrentHashMap

/**
 * Per-app firewall rules (RethinkDNS-style): ALLOW or BLOCK per UID.
 * Enforced in TcpProxy/UdpProxy before a connection is established.
 */
class FirewallManager(private val prefs: Prefs) {
    private val rules = ConcurrentHashMap<Int, Int>()
    private var selfUid = -1

    companion object {
        const val ALLOW = 0
        const val BLOCK = 1
    }

    init {
        load()
    }

    /** Our own UID is never firewalled (would break the VPN itself). */
    fun setSelfUid(uid: Int) {
        selfUid = uid
    }

    private fun load() {
        rules.clear()
        val raw = prefs.firewallRulesRaw()
        if (raw.isEmpty()) return
        for (part in raw.split(";")) {
            val f = part.split(":")
            if (f.size != 2) continue
            try {
                rules[f[0].toInt()] = f[1].toInt()
            } catch (_: NumberFormatException) {
            }
        }
    }

    private fun save() {
        val sb = StringBuilder()
        for ((k, v) in rules) {
            if (v == ALLOW) continue // default: don't persist
            if (sb.isNotEmpty()) sb.append(';')
            sb.append(k).append(':').append(v)
        }
        prefs.setFirewallRulesRaw(sb.toString())
    }

    fun ruleFor(uid: Int): Int = rules[uid] ?: ALLOW

    fun setRule(uid: Int, rule: Int) {
        if (rule == ALLOW) rules.remove(uid)
        else rules[uid] = rule
        save()
    }

    /** True when the firewall is on and this UID is blocked. */
    fun isBlocked(uid: Int): Boolean {
        if (!prefs.firewallEnabled()) return false
        if (uid == selfUid || uid < 0) return false
        return ruleFor(uid) == BLOCK
    }

    fun blockedCount(): Int {
        var n = 0
        for (r in rules.values) if (r == BLOCK) n++
        return n
    }
}
