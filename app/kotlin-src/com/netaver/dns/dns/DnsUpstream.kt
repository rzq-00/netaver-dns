package com.netaver.dns.dns

import java.io.IOException

/** Upstream DNS transport: plain UDP, DoT or DoH. */
interface DnsUpstream {
    /** Send query, return raw DNS response bytes. Throws on failure. */
    @Throws(IOException::class)
    fun query(q: ByteArray, qlen: Int): ByteArray
    fun close()
}
