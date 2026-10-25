package com.netaver.dns.dns

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.regex.Pattern

/** Minimal DNS wire-format parser/builder (RFC 1035). */
class DnsMessage private constructor() {

    var id: Int = 0
    var qname: String? = null   // lowercase, no trailing dot
    var qtype: Int = 0          // 1=A, 28=AAAA, ...
    var ok: Boolean = false

    companion object {
        private val DOT: Pattern = Pattern.compile("\\.")

        /** Java String.split(regex) semantics (trailing empties dropped, "" -> [""]). */
        private fun splitDot(s: String): List<String> = DOT.split(s).toList()

        /** Build a minimal DNS query for name/qtype (used for bootstrap resolution). */
        @JvmStatic
        fun buildQuery(name: String, qtype: Int): ByteArray? {
            return try {
                val out = ByteArrayOutputStream()
                val id = SecureRandom().nextInt(65536)
                writeShort(out, id)
                writeShort(out, 0x0100) // RD=1
                writeShort(out, 1) // QDCOUNT
                writeShort(out, 0) // ANCOUNT
                writeShort(out, 0) // NSCOUNT
                writeShort(out, 0) // ARCOUNT
                for (label in splitDot(name.lowercase())) {
                    val lb = label.toByteArray(StandardCharsets.US_ASCII)
                    if (lb.isEmpty() || lb.size > 63) return null
                    out.write(lb.size)
                    out.write(lb)
                }
                out.write(0)
                writeShort(out, qtype)
                writeShort(out, 1) // IN
                out.toByteArray()
            } catch (e: Exception) {
                null
            }
        }

        /** Parse a DNS query. Returns message with ok=false on malformed input. */
        @JvmStatic
        fun parseQuery(data: ByteArray, len: Int): DnsMessage {
            val m = DnsMessage()
            try {
                if (len < 12) return m
                var b = ByteBuffer.wrap(data, 0, len).order(ByteOrder.BIG_ENDIAN)
                m.id = b.short.toInt() and 0xFFFF
                val flags = b.short.toInt() and 0xFFFF
                val isQuery = flags and 0x8000 == 0
                val qdcount = b.short.toInt() and 0xFFFF
                b.short // ANCOUNT
                b.short // NSCOUNT
                b.short // ARCOUNT
                if (!isQuery || qdcount != 1) return m
                val name = StringBuilder()
                // QNAME with compression-pointer safety. E6: pointer jumps
                // and label steps are counted separately — the old single
                // counter rejected legal names with more than 16 labels.
                var jumps = 0
                var steps = 0
                // qtype/qclass follow the POINTER (original offset + 2), not the target
                var afterPtr = -1
                while (true) {
                    if (!b.hasRemaining() || steps++ > 128) return m
                    val lbl = b.get().toInt() and 0xFF
                    if (lbl == 0) break
                    if (lbl and 0xC0 == 0xC0) {
                        if (++jumps > 16) return m
                        if (!b.hasRemaining()) return m
                        val ptr = ((lbl and 0x3F) shl 8) or (b.get().toInt() and 0xFF)
                        if (ptr >= len) return m
                        if (afterPtr < 0) afterPtr = b.position()
                        // follow pointer in a sub-buffer
                        b = ByteBuffer.wrap(data, ptr, len - ptr).order(ByteOrder.BIG_ENDIAN)
                        continue
                    }
                    if (lbl > 63 || b.remaining() < lbl) return m
                    if (name.isNotEmpty()) name.append('.')
                    val part = ByteArray(lbl)
                    b.get(part)
                    name.append(String(part, StandardCharsets.US_ASCII).lowercase())
                    if (name.length > 253) return m
                }
                if (afterPtr >= 0) {
                    if (afterPtr + 4 > len) return m
                    b = ByteBuffer.wrap(data, afterPtr, len - afterPtr).order(ByteOrder.BIG_ENDIAN)
                }
                if (b.remaining() < 4) return m
                m.qtype = b.short.toInt() and 0xFFFF
                // val qclass = b.short.toInt() and 0xFFFF
                m.qname = name.toString()
                m.ok = name.isNotEmpty()
                return m
            } catch (e: Exception) {
                return m
            }
        }

        /** Build a "blocked" response: NOERROR with null-routed address for A/AAAA. */
        @JvmStatic
        fun buildBlockedResponse(q: DnsMessage): ByteArray? {
            return try {
                val out = ByteArrayOutputStream()
                writeShort(out, q.id)
                writeShort(out, 0x8180) // QR=1, RD=1, RA=1, NOERROR
                writeShort(out, 1)      // QDCOUNT
                writeShort(out, if (q.qtype == 1 || q.qtype == 28) 1 else 0) // ANCOUNT
                writeShort(out, 0)
                writeShort(out, 0)
                writeQuestion(out, q)
                if (q.qtype == 1 || q.qtype == 28) {
                    // answer: pointer to QNAME, type, class IN, TTL 60, RDATA
                    out.write(0xC0); out.write(0x0C)
                    writeShort(out, q.qtype)
                    writeShort(out, 1)
                    writeInt(out, 60)
                    if (q.qtype == 1) {
                        writeShort(out, 4)
                        out.write(byteArrayOf(0, 0, 0, 0))
                    } else {
                        writeShort(out, 16)
                        out.write(ByteArray(16))
                    }
                }
                out.toByteArray()
            } catch (e: Exception) {
                null
            }
        }

        /** Build a SERVFAIL response (upstream unreachable). */
        @JvmStatic
        fun buildServFail(q: DnsMessage): ByteArray? {
            return try {
                val out = ByteArrayOutputStream()
                writeShort(out, q.id)
                writeShort(out, 0x8182) // QR=1, RCODE=2 SERVFAIL
                writeShort(out, 1)
                writeShort(out, 0)
                writeShort(out, 0)
                writeShort(out, 0)
                writeQuestion(out, q)
                out.toByteArray()
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Build a truncated response (TC set, question echoed, no answers):
         * tells the client to retry over TCP. Used when the real answer
         * cannot fit into a single UDP packet.
         */
        @JvmStatic
        fun buildTruncatedResponse(q: DnsMessage): ByteArray? {
            return try {
                val out = ByteArrayOutputStream()
                writeShort(out, q.id)
                writeShort(out, 0x8380) // QR=1, TC=1, RD=1, RA=1, NOERROR
                writeShort(out, 1)      // QDCOUNT
                writeShort(out, 0)      // ANCOUNT
                writeShort(out, 0)
                writeShort(out, 0)
                writeQuestion(out, q)
                out.toByteArray()
            } catch (e: Exception) {
                null
            }
        }

        private fun writeQuestion(out: ByteArrayOutputStream, q: DnsMessage) {
            // q.qname!! : null qname throws (caught by caller -> null), same as Java
            for (label in splitDot(q.qname!!)) {
                val lb = label.toByteArray(StandardCharsets.US_ASCII)
                out.write(lb.size)
                out.write(lb)
            }
            out.write(0)
            writeShort(out, q.qtype)
            writeShort(out, 1) // IN
        }

        private fun writeShort(out: ByteArrayOutputStream, v: Int) {
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }

        private fun writeInt(out: ByteArrayOutputStream, v: Int) {
            out.write((v shr 24) and 0xFF)
            out.write((v shr 16) and 0xFF)
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }

        /** Extract resolved IPs (A/AAAA) from a DNS response. Max 3, for logging. */
        @JvmStatic
        fun extractIps(resp: ByteArray?, len: Int): List<String> {
            val out = ArrayList<String>()
            try {
                if (resp == null || len < 12) return out
                val qdcount = ((resp[4].toInt() and 0xFF) shl 8) or (resp[5].toInt() and 0xFF)
                val ancount = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
                if (ancount == 0 || ancount > 64) return out
                var off = 12
                for (i in 0 until qdcount) {
                    off = skipName(resp, len, off)
                    if (off < 0 || off + 4 > len) return out
                    off += 4
                }
                for (i in 0 until ancount) {
                    if (out.size >= 3) break
                    off = skipName(resp, len, off)
                    if (off < 0 || off + 10 > len) return out
                    val type = ((resp[off].toInt() and 0xFF) shl 8) or (resp[off + 1].toInt() and 0xFF)
                    val rdlen = ((resp[off + 8].toInt() and 0xFF) shl 8) or (resp[off + 9].toInt() and 0xFF)
                    off += 10
                    if (off + rdlen > len || rdlen < 0) return out
                    if (type == 1 && rdlen == 4) {
                        out.add("${resp[off].toInt() and 0xFF}.${resp[off + 1].toInt() and 0xFF}." +
                                "${resp[off + 2].toInt() and 0xFF}.${resp[off + 3].toInt() and 0xFF}")
                    } else if (type == 28 && rdlen == 16) {
                        val b6 = ByteArray(16)
                        System.arraycopy(resp, off, b6, 0, 16)
                        try {
                            out.add(java.net.InetAddress.getByAddress(b6).hostAddress)
                        } catch (ignored: Exception) {}
                    }
                    off += rdlen
                }
            } catch (ignored: Exception) {}
            return out
        }

        /** Skip a DNS name (labels or compression pointer). Returns new offset or -1. */
        private fun skipName(b: ByteArray, len: Int, off: Int): Int {
            var o = off
            // B2: bound total label STEPS (128), not steps-plus-jumps at
            // 16 — a legal name with many labels must not fail the skip
            // (same discipline as parseQuery after E6). Pointers still
            // return immediately, as before.
            var steps = 0
            while (o < len && steps++ <= 128) {
                val lbl = b[o].toInt() and 0xFF
                if (lbl == 0) return o + 1
                if (lbl and 0xC0 == 0xC0) return o + 2
                o += 1 + lbl
            }
            return -1
        }

        /**
         * Minimum TTL (seconds) across answer records, or -1 if the response
         * is not cacheable (error, no answers, zero TTL, malformed).
         */
        @JvmStatic
        fun minTtl(resp: ByteArray?, len: Int): Long {
            try {
                if (resp == null || len < 12) return -1
                // E8: only complete responses are cacheable — QR clear means
                // this is not a response at all, TC set means the answer was
                // truncated (caching it would serve a partial answer as whole)
                if (resp[2].toInt() and 0x80 == 0) return -1 // QR bit
                if (resp[2].toInt() and 0x02 != 0) return -1 // TC bit
                if (resp[3].toInt() and 0x0F != 0) return -1 // rcode != NOERROR
                val qdcount = u16(resp, 4)
                val ancount = u16(resp, 6)
                if (ancount == 0 || ancount > 64 || qdcount > 8) return -1
                var off = 12
                for (i in 0 until qdcount) {
                    off = skipName(resp, len, off)
                    if (off < 0 || off + 4 > len) return -1
                    off += 4
                }
                var min = Long.MAX_VALUE
                for (i in 0 until ancount) {
                    off = skipName(resp, len, off)
                    if (off < 0 || off + 10 > len) return -1
                    // layout: TYPE(2) CLASS(2) TTL(4) RDLEN(2)
                    val ttl = ((resp[off + 4].toLong() and 0xFFL) shl 24) or
                            ((resp[off + 5].toLong() and 0xFFL) shl 16) or
                            ((resp[off + 6].toLong() and 0xFFL) shl 8) or
                            (resp[off + 7].toLong() and 0xFFL)
                    val rdlen = u16(resp, off + 8)
                    off += 10
                    if (rdlen < 0 || off + rdlen > len) return -1
                    off += rdlen
                    if (ttl < min) min = ttl
                }
                return if (min == Long.MAX_VALUE || min <= 0) -1 else min
            } catch (e: Exception) {
                return -1
            }
        }

        private fun u16(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

        @JvmStatic
        fun qtypeName(t: Int): String = when (t) {
            1 -> "A"
            2 -> "NS"
            5 -> "CNAME"
            6 -> "SOA"
            15 -> "MX"
            16 -> "TXT"
            28 -> "AAAA"
            33 -> "SRV"
            255 -> "ANY"
            else -> "T$t"
        }
    }
}
