package com.netaver.dns.dns

import java.util.Collections
import java.util.LinkedHashMap

/**
 * In-memory DNS response cache (honors upstream TTLs).
 * Repeated queries for the same (name, type) are answered locally:
 * faster + fewer upstream connections (battery-friendly, esp. for DoT/DoH).
 * Thread-safe. Cleared on network reconnect.
 */
class DnsCache {

    private class Entry {
        var resp: ByteArray = ByteArray(0) // upstream response bytes (query ID rewritten on serve)
        var expiresAt: Long = 0
    }

    private val map: MutableMap<String, Entry> = Collections.synchronizedMap(
        object : LinkedHashMap<String, Entry>(128, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean {
                return size > MAX_ENTRIES
            }
        })

    /** Store an upstream response if cacheable (positive answer, TTL > 0). */
    fun put(qname: String, qtype: Int, resp: ByteArray?, len: Int) {
        if (resp == null || len <= 0) return
        val ttlSec = DnsMessage.minTtl(resp, len)
        if (ttlSec <= 0) return
        val e = Entry()
        val copy = ByteArray(len)
        System.arraycopy(resp, 0, copy, 0, len)
        e.resp = copy
        e.expiresAt = System.currentTimeMillis() + minOf(ttlSec * 1000, MAX_TTL_MS)
        map[key(qname, qtype)] = e
    }

    /**
     * Serve from cache with the query ID rewritten to the caller's ID,
     * or null on miss/expiry.
     */
    fun get(qname: String, qtype: Int, queryId: Int): ByteArray? {
        val k = key(qname, qtype)
        val e = map[k] ?: return null
        if (System.currentTimeMillis() > e.expiresAt) {
            map.remove(k)
            return null
        }
        val out = e.resp.clone()
        out[0] = ((queryId shr 8) and 0xFF).toByte()
        out[1] = (queryId and 0xFF).toByte()
        return out
    }

    fun clear() { map.clear() }

    fun size(): Int = map.size

    companion object {
        private const val MAX_ENTRIES = 1000
        private const val MAX_TTL_MS = 3_600_000L // clamp TTL to 1h

        private fun key(qname: String, qtype: Int): String = "$qtype|$qname"
    }
}
