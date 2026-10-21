package com.netaver.dns.dns

/**
 * Domain blocklist matcher. Matches exact domains and any subdomain
 * (blocking "ads.example.com" also blocks "x.ads.example.com").
 * Supports multiple named sources so a hit can be attributed to its list.
 * Thread-safe for reads after load; swap the whole map on update.
 */
class Blocklist {
    @Volatile
    private var sources: Map<String, Set<String>> = LinkedHashMap()

    /** Replace with a single unnamed source (legacy). */
    fun replace(newSet: Set<String>) {
        val m = LinkedHashMap<String, Set<String>>()
        m[""] = newSet
        sources = m
    }

    /** Replace with named sources (insertion order = attribution priority). */
    fun replaceSources(newSources: Map<String, Set<String>>) {
        sources = LinkedHashMap(newSources)
    }

    fun size(): Int {
        var n = 0
        for (s in sources.values) n += s.size
        return n
    }

    fun isBlocked(domain: String?): Boolean = matchSource(domain) != null

    /** Returns the source key that matched, or null. */
    fun matchSource(domain: String?): String? {
        if (domain.isNullOrEmpty()) return null
        val src = sources
        if (src.isEmpty()) return null
        var d = domain.lowercase()
        if (d.endsWith(".")) d = d.substring(0, d.length - 1)
        // walk up: sub.ads.example.com -> ads.example.com -> example.com
        while (true) {
            for ((key, set) in src) {
                if (set.contains(d)) return key
            }
            val dot = d.indexOf('.')
            if (dot < 0) return null
            d = d.substring(dot + 1)
        }
    }

    companion object {
        /** Parse one line of a blocklist into a domain, or null if not usable. */
        @JvmStatic
        /** Parse one blocklist line; may yield multiple domains (hosts lines). */
        fun parseLine(line: String?): List<String> {
            if (line == null) return emptyList()
            var l = line.trim()
            if (l.isEmpty() || l.startsWith("#")) return emptyList()
            // strip inline comments
            val hash = l.indexOf('#')
            if (hash >= 0) l = l.substring(0, hash).trim()
            if (l.isEmpty()) return emptyList()

            // AdBlock style: ||domain^ or ||domain^$third-party
            if (l.startsWith("||")) {
                var end = l.indexOf('^')
                if (end < 0) end = l.length
                var d = l.substring(2, end).trim().lowercase()
                // strip wildcard the same way as the "*.domain" branch below
                if (d.startsWith("*.")) d = d.substring(2)
                return if (validDomain(d)) listOf(d) else emptyList()
            }
            // hosts style: "0.0.0.0 d1.com d2.com" — collect ALL domains after the IP
            val parts = l.split("\\s+".toRegex())
            if (parts.size > 1 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" ||
                        parts[0] == "::" || parts[0] == "::1")) {
                return parts.subList(1, parts.size)
                    .map { it.lowercase() }
                    .filter { validDomain(it) }
            }
            // wildcard format: "*.domain.com" -> "domain.com"
            // (subdomain matching already covers all subdomains)
            var candidate = parts[parts.size - 1].lowercase()
            if (candidate.startsWith("*.")) {
                candidate = candidate.substring(2)
            }
            // plain domain list: single token that looks like a domain
            if (parts.size == 1) {
                return if (validDomain(candidate)) listOf(candidate) else emptyList()
            }
            return emptyList()
        }

        private fun validDomain(d: String?): Boolean {
            if (d == null || d.length < 3 || d.length > 253) return false
            if (d.startsWith(".") || d.endsWith(".") || d.startsWith("-")) return false
            if (!d.contains(".")) return false
            for (c in d) {
                if (c !in 'a'..'z' && c !in '0'..'9' && c != '.' && c != '-' && c != '_') {
                    if (c == '*') return false // skip wildcards for v1
                    return false
                }
            }
            return true
        }
    }
}
