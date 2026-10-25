package com.netaver.dns.dns

import android.net.VpnService

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException

/** Plain DNS over UDP (port 53). */
class PlainUpstream(vpn: VpnService, ip: String) : DnsUpstream {
    private val sock: DatagramSocket
    private val server: InetAddress
    private val respBuf = ByteArray(65535)
    private val timeoutMs = 3000

    init {
        sock = DatagramSocket()
        vpn.protect(sock)
        sock.soTimeout = timeoutMs
        server = InetAddress.getByName(ip)
        // M2: connect() makes the kernel drop packets from any other
        // source address/port — an unconnected UDP socket otherwise
        // accepts "answers" from anyone on the LAN (poisoning vector).
        sock.connect(server, 53)
    }

    @Synchronized
    @Throws(IOException::class)
    override fun query(q: ByteArray, qlen: Int): ByteArray {
        sock.send(DatagramPacket(q, qlen, server, 53))
        // M2: accept only the answer to THIS query — QR set, TXID equal,
        // question echoed identically. Anything else is discarded and we
        // keep waiting until the timeout deadline expires.
        val want = DnsMessage.parseQuery(q, qlen)
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remain = deadline - System.currentTimeMillis()
            if (remain <= 0) throw SocketTimeoutException("plain DNS timeout")
            sock.soTimeout = remain.toInt().coerceAtLeast(1)
            val incoming = DatagramPacket(respBuf, respBuf.size)
            sock.receive(incoming)
            val len = incoming.length
            if (len < 12) continue
            if ((respBuf[2].toInt() and 0x80) == 0) continue // QR must be set
            if (respBuf[0] != q[0] || respBuf[1] != q[1]) continue // TXID
            if (want.ok) {
                val rq = responseQuestion(respBuf, len) ?: continue
                if (rq.first != want.qname || rq.second != want.qtype) continue
            }
            val resp = ByteArray(len)
            System.arraycopy(respBuf, 0, resp, 0, len)
            return resp
        }
    }

    override fun close() {
        try { sock.close() } catch (_: Exception) {}
    }

    /**
     * Question (qname, qtype) of a DNS response, or null if unparseable.
     * DnsMessage.parseQuery() refuses QR=1 packets, so responses are
     * walked locally here with the same label/pointer discipline.
     */
    private fun responseQuestion(data: ByteArray, len: Int): Pair<String, Int>? {
        try {
            var p = 12
            val name = StringBuilder()
            // B2: same discipline as DnsMessage.parseQuery (E6) — label
            // steps bounded separately (128) from pointer jumps (16); the
            // old single counter rejected legal names with >16 labels.
            var jumps = 0
            var steps = 0
            var afterPtr = -1
            while (true) {
                if (p >= len || steps++ > 128) return null
                val lbl = data[p].toInt() and 0xFF
                if (lbl == 0) { p++; break }
                if ((lbl and 0xC0) == 0xC0) {
                    if (++jumps > 16) return null
                    if (p + 1 >= len) return null
                    val ptr = ((lbl and 0x3F) shl 8) or (data[p + 1].toInt() and 0xFF)
                    if (ptr >= len) return null
                    if (afterPtr < 0) afterPtr = p + 2
                    p = ptr
                    continue
                }
                if (lbl > 63 || p + 1 + lbl > len) return null
                if (name.isNotEmpty()) name.append('.')
                name.append(String(data, p + 1, lbl, Charsets.US_ASCII).lowercase())
                if (name.length > 253) return null
                p += 1 + lbl
            }
            val qpos = if (afterPtr >= 0) afterPtr else p
            if (qpos + 4 > len) return null
            val qtype = ((data[qpos].toInt() and 0xFF) shl 8) or
                    (data[qpos + 1].toInt() and 0xFF)
            if (name.isEmpty()) return null
            return name.toString() to qtype
        } catch (e: Exception) {
            return null
        }
    }
}
