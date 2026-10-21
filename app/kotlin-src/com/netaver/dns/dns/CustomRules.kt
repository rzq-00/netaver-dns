package com.netaver.dns.dns

import java.util.regex.Pattern

/**
 * User custom filtering rules, AdGuard Home style:
 *   ||domain.com^        block domain + subdomains
 *   @@||domain.com^      allowlist (exception, wins over everything)
 *   |domain.com|         block exact-ish (treated like ||domain^)
 *   domain.com           block domain + subdomains
 *   /regex/              block by regex
 *   @@/regex/            allow by regex
 *   ! comment            ignored
 * Modifiers after $ are stripped (e.g. ||x.com^$third-party).
 * Thread-safe: swap whole rule set on update.
 */
class CustomRules {

    internal class Rule(
        val allow: Boolean,
        /** lowercase, null if regex rule */
        val domain: String?,
        /** null if domain rule */
        val regex: Pattern?
    )

    @Volatile
    private var rules: List<Rule> = ArrayList()

    /** Parse rules text. Returns [blockCount, allowCount] for UI. */
    fun setText(text: String?): IntArray {
        val parsed = ArrayList<Rule>()
        var blocks = 0
        var allows = 0
        if (text != null) {
            for (raw in text.split("\n")) {
                val r = parseLine(raw) ?: continue
                parsed.add(r)
                if (r.allow) allows++ else blocks++
            }
        }
        rules = parsed
        return intArrayOf(blocks, allows)
    }

    fun count(): Int = rules.size

    /**
     * Match a domain. Returns 1=block, -1=allow, 0=no match.
     * Allowlist rules always win over block rules.
     */
    fun match(domain: String?): Int {
        if (domain.isNullOrEmpty()) return 0
        val rs = rules
        if (rs.isEmpty()) return 0
        val d = domain.lowercase()
        var blocked = false
        for (r in rs) {
            val hit = if (r.regex != null) {
                try { r.regex.matcher(d).find() } catch (e: Exception) { false }
            } else {
                domainMatch(d, r.domain!!)
            }
            if (!hit) continue
            if (r.allow) return -1 // allowlist wins immediately
            blocked = true
        }
        return if (blocked) 1 else 0
    }

    companion object {
        private fun domainMatch(d: String, rule: String): Boolean {
            var x = d
            while (true) {
                if (x == rule) return true
                val dot = x.indexOf('.')
                if (dot < 0) return false
                x = x.substring(dot + 1)
            }
        }

        internal fun parseLine(raw: String?): Rule? {
            if (raw == null) return null
            var line = raw.trim()
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("#")) return null

            var allow = false
            if (line.startsWith("@@")) {
                allow = true
                line = line.substring(2).trim()
                if (line.isEmpty()) return null
            }
            // strip $modifiers
            val dollar = line.indexOf('$')
            if (dollar >= 0) line = line.substring(0, dollar).trim()
            if (line.isEmpty()) return null

            // regex: /.../
            if (line.startsWith("/") && line.length > 2 && line.endsWith("/")) {
                return try {
                    val p = Pattern.compile(line.substring(1, line.length - 1))
                    Rule(allow, null, p)
                } catch (e: Exception) {
                    null // bad regex: ignore
                }
            }
            // ||domain^
            if (line.startsWith("||")) {
                val end = line.indexOf('^')
                var dom = (if (end >= 0) line.substring(2, end) else line.substring(2)).trim().lowercase()
                if (dom.startsWith("*.")) dom = dom.substring(2)
                return if (validRuleDomain(dom)) Rule(allow, dom, null) else null
            }
            // |domain|
            if (line.startsWith("|") && line.endsWith("|") && line.length > 2) {
                val dom = line.substring(1, line.length - 1).trim().lowercase()
                return if (validRuleDomain(dom)) Rule(allow, dom, null) else null
            }
            // plain domain
            if (line.startsWith("|")) line = line.substring(1)
            if (line.endsWith("^")) line = line.substring(0, line.length - 1)
            var dom = line.trim().lowercase()
            if (dom.startsWith("*.")) dom = dom.substring(2)
            return if (validRuleDomain(dom)) Rule(allow, dom, null) else null
        }

        private fun validRuleDomain(d: String?): Boolean {
            if (d == null || d.length < 3 || d.length > 253) return false
            if (d.contains("*") || d.contains("/") || d.contains(" ")) return false
            if (!d.contains(".")) return false
            for (c in d) {
                if (c !in 'a'..'z' && c !in '0'..'9' && c != '.' && c != '-' && c != '_')
                    return false
            }
            return true
        }
    }
}
