package com.netaver.dns.dns

import java.util.Collections
import java.util.LinkedHashMap

/**
 * In-memory DNS response cache (honors upstream TTLs).
 * Repeated queries for the same (name, type) are answered locally:
 * faster + fewer upstream connections (battery-friendly, esp. for DoT/DoH).
 * A user-configurable minimum-TTL floor applies (Settings, default
 * 600 s): positive answers are kept at least that long even when the
 * upstream TTL is shorter (many large services publish 30–60 s TTLs
 * while clients re-ask only minutes later; their addresses rotate
 * between simultaneously-live anycast pools, so the extra staleness
 * is harmless in practice — measured on the user's own logs: cache
 * share 1.3% (no floor) → 23% (5 min) → 36% (10 min)).
 * Optional optimistic caching: expired entries are served instantly
 * (marked stale) while the caller refreshes them in the background.
 * Thread-safe. Cleared on network reconnect.
 */
class DnsCache {

    @Volatile private var minTtlSec: Long = 600
    @Volatile private var optimistic: Boolean = true // E7: matches the Prefs default (was false)
    @Volatile private var maxEntries: Int = 5000

    /** Apply the user's cache settings (Settings screen / app start). */
    fun configure(minTtlSec: Int, optimistic: Boolean, maxEntries: Int) {
        this.minTtlSec = minTtlSec.toLong().coerceIn(0, 86400)
        this.optimistic = optimistic
        this.maxEntries = maxEntries.coerceIn(100, 10000)
    }

    private class Entry {
        var resp: ByteArray = ByteArray(0) // upstream response bytes (query ID rewritten on serve)
        var expiresAt: Long = 0
    }

    private val map: MutableMap<String, Entry> = Collections.synchronizedMap(
        object : LinkedHashMap<String, Entry>(128, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean {
                return size > maxEntries
            }
        })

    /** Store an upstream response if cacheable (positive answer, TTL > 0). */
    fun put(qname: String, qtype: Int, resp: ByteArray?, len: Int) {
        if (resp == null || len <= 0) return
        val ttlSec = DnsMessage.minTtl(resp, len)
        if (ttlSec <= 0) return
        val effSec = if (minTtlSec > 0) maxOf(ttlSec, minTtlSec) else ttlSec // minimum-TTL floor (user setting)
        val e = Entry()
        val copy = ByteArray(len)
        System.arraycopy(resp, 0, copy, 0, len)
        e.resp = copy
        e.expiresAt = System.currentTimeMillis() + minOf(effSec * 1000, MAX_TTL_MS)
        map[key(qname, qtype)] = e
    }

    /** A cache hit: the response bytes plus whether the entry had expired. */
    class Hit(val bytes: ByteArray, val stale: Boolean)

    /**
     * Look up an entry with the query ID rewritten to the caller's ID,
     * or null on miss. An expired entry counts as a miss unless
     * optimistic caching is on — then it is returned as a stale hit so
     * the caller can serve it instantly and refresh in the background.
     */
    fun lookup(qname: String, qtype: Int, queryId: Int): Hit? {
        val k = key(qname, qtype)
        val e = map[k] ?: return null
        val expired = System.currentTimeMillis() > e.expiresAt
        if (expired && !optimistic) {
            map.remove(k)
            return null
        }
        val out = e.resp.clone()
        out[0] = ((queryId shr 8) and 0xFF).toByte()
        out[1] = (queryId and 0xFF).toByte()
        return Hit(out, expired)
    }

    fun clear() { map.clear() }

    fun size(): Int = map.size

    companion object {
        private const val MAX_ENTRIES = 5000
        private const val MAX_TTL_MS = 3_600_000L // clamp TTL to 1h (internal cap)

        private fun key(qname: String, qtype: Int): String = "$qtype|$qname"
    }
}
