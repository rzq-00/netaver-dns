package com.netaver.dns.dns

import android.net.VpnService

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/** DNS-over-TLS (RFC 7858): 2-octet length framing over TLS on port 853. */
class DotUpstream(vpn: VpnService, ip: String, tlsHost: String) :
    TlsUpstream(vpn, ip, tlsHost, 853) {

    @Throws(IOException::class)
    override fun query(q: ByteArray, qlen: Int): ByteArray {
        ensure()
        try {
            val out: OutputStream = out()
            val input: InputStream = `in`()
            out.write((qlen shr 8) and 0xFF)
            out.write(qlen and 0xFF)
            out.write(q, 0, qlen)
            out.flush()
            val hi = input.read()
            val lo = input.read()
            if (hi < 0) throw IOException("DoT EOF")
            val rlen = ((hi shl 8) or lo) and 0xFFFF
            // M3: a DNS message may legally reach 65535 B (RFC max) — the
            // old 4096 cap rejected legitimate large answers
            if (rlen <= 0 || rlen > 65535) throw IOException("DoT bad length: $rlen")
            val resp = ByteArray(rlen)
            readFully(input, resp, rlen)
            return resp
        } catch (e: IOException) {
            onFailure(e)
            throw e
        }
    }
}
