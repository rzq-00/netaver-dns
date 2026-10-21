package com.netaver.dns.net

import com.netaver.dns.DnsVpnService

/**
 * IPv6 "No": actively reject IPv6 traffic instead of silently dropping it,
 * so apps fail fast and fall back to IPv4 (Happy Eyeballs) instead of
 * hanging on "Checking..." forever.
 * TCP -> RST|ACK, UDP -> ICMPv6 Port Unreachable. Everything else dropped.
 */
class Ip6Reject private constructor() {
    companion object {
        private const val IPV6_HDR = 40

        @JvmStatic
        fun maybeReject(vpn: DnsVpnService, buf: ByteArray, len: Int) {
            val out = buildReject(buf, len)
            if (out != null) vpn.writeTun(out, out.size)
        }

        /**
         * Build the rejection packet, or null to drop silently. Package-visible for tests.
         * (Kotlin `internal` mirrors Java package visibility within this module.)
         */
        @JvmStatic
        internal fun buildReject(buf: ByteArray?, len: Int): ByteArray? {
            if (buf == null || len < IPV6_HDR + 8) return null
            if (((buf[0].toInt() shr 4) and 0xF) != 6) return null
            if ((buf[24].toInt() and 0xFF) == 0xFF) return null // multicast: never answer
            val next = buf[6].toInt() and 0xFF
            if (next == 6) return buildTcpRst(buf, len)
            if (next == 17) return buildIcmpv6Unreachable(buf, len)
            return null // ICMPv6 / extension headers / fragments: drop
        }

        private fun buildTcpRst(ip: ByteArray, len: Int): ByteArray? {
            val t = IPV6_HDR
            if (len < t + 20) return null
            val tcpHdrLen = ((ip[t + 12].toInt() shr 4) and 0xF) * 4
            if (tcpHdrLen < 20 || len < t + tcpHdrLen) return null
            val flags = ip[t + 13].toInt() and 0xFF
            if ((flags and 0x04) != 0) return null // already RST, ignore

            val srcPort = u16(ip, t)
            val dstPort = u16(ip, t + 2)
            val seq = u32(ip, t + 4)
            val ipPayLen = u16(ip, 4)
            val dataLen = maxOf(0, ipPayLen - tcpHdrLen)
            var rack = seq + dataLen
            if ((flags and 0x02) != 0) rack += 1 // SYN
            if ((flags and 0x01) != 0) rack += 1 // FIN

            val out = ByteArray(IPV6_HDR + 20)
            out[0] = 0x60             // version 6
            put16(out, 4, 20)         // payload length
            out[6] = 6                // TCP
            out[7] = 64               // hop limit
            System.arraycopy(ip, 24, out, 8, 16)   // src = orig dst
            System.arraycopy(ip, 8, out, 24, 16)   // dst = orig src
            put16(out, t, dstPort)
            put16(out, t + 2, srcPort)
            put32(out, t + 4, 0)      // seq
            put32(out, t + 8, rack)   // ack
            out[t + 12] = 0x50        // data offset 5
            out[t + 13] = 0x14        // RST|ACK
            put16(out, t + 16, checksum6(out, 8, out, 24, 6, out, t, 20))
            return out
        }

        private fun buildIcmpv6Unreachable(ip: ByteArray, len: Int): ByteArray? {
            val copyLen = minOf(len - IPV6_HDR, 48) // orig IPv6 hdr + 8 bytes
            if (copyLen < 8) return null
            val total = IPV6_HDR + 8 + copyLen
            val out = ByteArray(total)
            out[0] = 0x60
            put16(out, 4, 8 + copyLen)
            out[6] = 58               // ICMPv6
            out[7] = 64
            System.arraycopy(ip, 24, out, 8, 16)
            System.arraycopy(ip, 8, out, 24, 16)
            val ic = IPV6_HDR
            out[ic] = 1               // Destination Unreachable
            out[ic + 1] = 4           // Port Unreachable
            // ic+2..ic+3 checksum, ic+4..ic+7 unused = 0
            System.arraycopy(ip, 0, out, ic + 8, copyLen)
            put16(out, ic + 2, checksum6(out, 8, out, 24, 58, out, ic, 8 + copyLen))
            return out
        }

        /** TCP/UDP/ICMPv6 checksum with IPv6 pseudo-header. */
        private fun checksum6(s: ByteArray, sOff: Int, d: ByteArray, dOff: Int,
                             next: Int, p: ByteArray, pOff: Int, pLen: Int): Int {
            var sum = 0L
            sum = add(sum, s, sOff, 16)
            sum = add(sum, d, dOff, 16)
            sum += (pLen ushr 16).toLong()
            sum += (pLen and 0xFFFF).toLong()
            sum += (next and 0xFF).toLong()
            sum = add(sum, p, pOff, pLen)
            while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
            return (sum.inv() and 0xFFFF).toInt()
        }

        private fun add(sum: Long, b: ByteArray, off: Int, len: Int): Long {
            var s = sum
            var i = 0
            while (i + 1 < len) {
                s += ((b[off + i].toInt() and 0xFF) shl 8) or (b[off + i + 1].toInt() and 0xFF)
                i += 2
            }
            if (i < len) s += (b[off + i].toInt() and 0xFF) shl 8
            return s
        }

        private fun u16(b: ByteArray, o: Int): Int =
            ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

        private fun u32(b: ByteArray, o: Int): Long =
            ((b[o].toLong() and 0xFFL) shl 24) or ((b[o + 1].toLong() and 0xFFL) shl 16) or
                    ((b[o + 2].toLong() and 0xFFL) shl 8) or (b[o + 3].toLong() and 0xFFL)

        private fun put16(b: ByteArray, o: Int, v: Int) {
            b[o] = (v shr 8).toByte()
            b[o + 1] = v.toByte()
        }

        private fun put32(b: ByteArray, o: Int, v: Long) {
            b[o] = (v shr 24).toByte()
            b[o + 1] = (v shr 16).toByte()
            b[o + 2] = (v shr 8).toByte()
            b[o + 3] = v.toByte()
        }
    }
}
