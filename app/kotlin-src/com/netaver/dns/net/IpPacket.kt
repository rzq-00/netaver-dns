package com.netaver.dns.net

/**
 * IPv4/TCP/UDP packet parse + build helpers over a shared byte[].
 * Zero-allocation on the parse path (views over the TUN buffer).
 */
class IpPacket private constructor(
    val buf: ByteArray,
    val len: Int,
    val ipHeaderLen: Int,
    val protocol: Int,
    val srcIp: Int,
    val dstIp: Int
) {
    fun transportOffset(): Int = ipHeaderLen

    // ---- TCP ----
    fun tcpSrcPort(): Int = getShort(buf, ipHeaderLen)
    fun tcpDstPort(): Int = getShort(buf, ipHeaderLen + 2)
    fun tcpSeq(): Long = getInt(buf, ipHeaderLen + 4).toLong() and 0xFFFFFFFFL
    fun tcpAck(): Long = getInt(buf, ipHeaderLen + 8).toLong() and 0xFFFFFFFFL
    fun tcpFlags(): Int = buf[ipHeaderLen + 13].toInt() and 0xFF
    fun tcpHeaderLen(): Int = ((buf[ipHeaderLen + 12].toInt() shr 4) and 0xF) * 4
    fun tcpPayloadOffset(): Int = ipHeaderLen + tcpHeaderLen()
    fun tcpPayloadLen(): Int = len - tcpPayloadOffset()

    // ---- UDP ----
    fun udpSrcPort(): Int = getShort(buf, ipHeaderLen)
    fun udpDstPort(): Int = getShort(buf, ipHeaderLen + 2)
    fun udpPayloadOffset(): Int = ipHeaderLen + 8
    fun udpPayloadLen(): Int = len - udpPayloadOffset()

    companion object {
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17
        const val PROTO_ICMP = 1

        /** Parse; returns null if not a valid IPv4 packet. */
        @JvmStatic
        fun parse(buf: ByteArray, len: Int): IpPacket? {
            if (len < 20) return null
            val verIhl = buf[0].toInt() and 0xFF
            if ((verIhl shr 4) != 4) return null
            val ihl = (verIhl and 0x0F) * 4
            if (ihl < 20 || len < ihl) return null
            var total = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
            if (total > len) total = len
            if (total < ihl) return null // corrupt: total length smaller than header
            val frag = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
            if ((frag and 0x1FFF) != 0 || (frag and 0x2000) != 0) return null // no fragments in v1
            val proto = buf[9].toInt() and 0xFF
            // transport header must be fully present; otherwise accessors like
            // tcpDstPort() would read out of bounds and kill the TUN loop
            if (proto == PROTO_TCP && total < ihl + 20) return null
            if (proto == PROTO_UDP && total < ihl + 8) return null
            val src = getInt(buf, 12)
            val dst = getInt(buf, 16)
            return IpPacket(buf, total, ihl, proto, src, dst)
        }

        @JvmStatic
        fun getShort(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

        @JvmStatic
        fun getInt(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
                    ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

        @JvmStatic
        fun putShort(b: ByteArray, off: Int, v: Int) {
            b[off] = (v shr 8).toByte()
            b[off + 1] = v.toByte()
        }

        @JvmStatic
        fun putInt(b: ByteArray, off: Int, v: Int) {
            b[off] = (v shr 24).toByte()
            b[off + 1] = (v shr 16).toByte()
            b[off + 2] = (v shr 8).toByte()
            b[off + 3] = v.toByte()
        }

        @JvmStatic
        fun ipToString(ip: Int): String =
            "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

        // ---------- builders ----------

        /** Build IPv4/UDP packet. Returns total length. */
        @JvmStatic
        fun buildUdp(out: ByteArray, srcIp: Int, dstIp: Int,
                     srcPort: Int, dstPort: Int, payload: ByteArray?, poff: Int, plen: Int): Int {
            val total = 20 + 8 + plen
            out[0] = 0x45
            out[1] = 0
            putShort(out, 2, total)
            putShort(out, 4, 0x1234)
            putShort(out, 6, 0x4000) // DF
            out[8] = 64
            out[9] = PROTO_UDP.toByte()
            putShort(out, 10, 0)
            putInt(out, 12, srcIp)
            putInt(out, 16, dstIp)
            putShort(out, 20, srcPort)
            putShort(out, 22, dstPort)
            putShort(out, 24, 8 + plen)
            putShort(out, 26, 0) // UDP checksum optional for IPv4
            System.arraycopy(payload, poff, out, 28, plen)
            putShort(out, 10, ipChecksum(out, 0, 20))
            return total
        }

        /** Build IPv4/TCP packet. Returns total length. */
        @JvmStatic
        fun buildTcp(out: ByteArray, srcIp: Int, dstIp: Int,
                     srcPort: Int, dstPort: Int,
                     seq: Long, ack: Long, flags: Int, window: Int,
                     payload: ByteArray?, poff: Int, plen: Int): Int {
            val total = 20 + 20 + plen
            out[0] = 0x45
            out[1] = 0
            putShort(out, 2, total)
            putShort(out, 4, 0x1234)
            putShort(out, 6, 0x4000)
            out[8] = 64
            out[9] = PROTO_TCP.toByte()
            putShort(out, 10, 0)
            putInt(out, 12, srcIp)
            putInt(out, 16, dstIp)
            putShort(out, 20, srcPort)
            putShort(out, 22, dstPort)
            putInt(out, 24, seq.toInt())
            putInt(out, 28, ack.toInt())
            out[32] = 0x50 // data offset 5
            out[33] = flags.toByte()
            putShort(out, 34, window)
            putShort(out, 36, 0) // checksum later
            putShort(out, 38, 0)
            if (plen > 0) System.arraycopy(payload, poff, out, 40, plen)
            putShort(out, 10, ipChecksum(out, 0, 20))
            putShort(out, 36, tcpChecksum(out, srcIp, dstIp, 20, 20 + plen))
            return total
        }

        @JvmStatic
        fun ipChecksum(b: ByteArray, off: Int, len: Int): Int {
            var sum = 0L
            var i = 0
            while (i < len) {
                sum += (((b[off + i].toInt() and 0xFF) shl 8) or (b[off + i + 1].toInt() and 0xFF)).toLong()
                i += 2
            }
            while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
            return (sum.inv() and 0xFFFF).toInt()
        }

        /** TCP checksum over pseudo-header + TCP segment. tcpOff/len cover the TCP part. */
        @JvmStatic
        fun tcpChecksum(b: ByteArray, srcIp: Int, dstIp: Int, tcpOff: Int, tcpLen: Int): Int {
            var sum = 0L
            sum += ((srcIp shr 16) and 0xFFFF).toLong()
            sum += (srcIp and 0xFFFF).toLong()
            sum += ((dstIp shr 16) and 0xFFFF).toLong()
            sum += (dstIp and 0xFFFF).toLong()
            sum += PROTO_TCP.toLong()
            sum += tcpLen.toLong()
            var i = 0
            while (i < tcpLen - 1) {
                sum += (((b[tcpOff + i].toInt() and 0xFF) shl 8) or (b[tcpOff + i + 1].toInt() and 0xFF)).toLong()
                i += 2
            }
            if ((tcpLen and 1) != 0) sum += ((b[tcpOff + tcpLen - 1].toInt() and 0xFF) shl 8).toLong()
            while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
            return (sum.inv() and 0xFFFF).toInt()
        }

        // flag constants
        const val FIN = 0x01
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10
    }
}
