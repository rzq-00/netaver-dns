package com.netaver.dns.dns

import com.netaver.dns.DnsVpnService
import com.netaver.dns.net.IpPacket
import com.netaver.dns.util.AppResolver

import java.io.ByteArrayOutputStream
import java.util.HashMap
import java.security.SecureRandom

/**
 * Terminates DNS-over-TCP (port 53) locally so it can't bypass the filter.
 * Minimal TCP server: handshake, in-order data, length-prefixed DNS messages
 * (RFC 1035 section 4.2.2), graceful close. Runs on the TUN thread for packet
 * handling; query processing is handed to DnsVpnService's TCP worker.
 */
class TcpDns(private val svc: DnsVpnService) {
    private val random = SecureRandom()
    private val sessions = HashMap<Long, Session>()
    private var packetCount = 0

    /** A query extracted from a session, ready for the worker thread. */
    class Task internal constructor(
        val session: Session,
        val query: ByteArray,
        val uid: Int,
        val app: String,
        /** "" or hardcoded DNS IP the app tried */
        val bypassServer: String
    )

    class Session {
        var srcIp: Int = 0
        var dstIp: Int = 0
        var srcPort: Int = 0
        var mySeq: Long = 0      // next sequence number we will send
        var theirAck: Long = 0   // next sequence number we expect from client
        val buf = ByteArrayOutputStream()
        var lastActive: Long = System.currentTimeMillis()
        var uid: Int = -100
        var app: String = ""
    }

    companion object {
        private fun key(srcIp: Int, srcPort: Int): Long =
            ((srcIp.toLong() and 0xFFFFFFFFL) shl 32) or (srcPort.toLong() and 0xFFFFL)
    }

    /** Called on the TUN thread for every TCP packet to port 53. */
    @Synchronized
    fun handle(p: IpPacket) {
        if ((++packetCount and 0xFF) == 0) cleanup()
        val flags = p.tcpFlags()
        val k = key(p.srcIp, p.tcpSrcPort())

        if (flags and IpPacket.SYN != 0 && flags and IpPacket.ACK == 0) {
            // new connection
            val s = Session()
            s.srcIp = p.srcIp
            s.dstIp = p.dstIp
            s.srcPort = p.tcpSrcPort()
            s.mySeq = random.nextInt().toLong() and 0xFFFFFFFFL
            s.theirAck = (p.tcpSeq().toLong() + 1) and 0xFFFFFFFFL
            sessions[k] = s
            send(s, IpPacket.SYN or IpPacket.ACK, null, 0, 0)
            s.mySeq = (s.mySeq + 1) and 0xFFFFFFFFL // SYN consumes one
            // resolve owner once per connection (cheap, cached)
            s.uid = svc.resolver().uidFor(AppResolver.protoTcp(), p.srcIp, p.tcpSrcPort(), p.dstIp, 53)
            s.app = svc.resolver().labelForUid(s.uid)
            return
        }

        val s = sessions[k]
        if (s == null) {
            // unknown session: reset so the client retries cleanly
            sendReset(p)
            return
        }
        s.lastActive = System.currentTimeMillis()
        if (flags and IpPacket.RST != 0) {
            sessions.remove(k)
            return
        }
        val payloadLen = p.tcpPayloadLen()
        if (payloadLen > 0) {
            val seq = p.tcpSeq().toLong() and 0xFFFFFFFFL
            if (seq != s.theirAck) {
                // duplicate/retransmitted segment: re-ACK, don't append twice
                send(s, IpPacket.ACK, null, 0, 0)
            } else {
                val payload = ByteArray(payloadLen)
                System.arraycopy(p.buf, p.tcpPayloadOffset(), payload, 0, payloadLen)
                s.theirAck = (seq + payloadLen) and 0xFFFFFFFFL
                s.buf.write(payload, 0, payloadLen)
                send(s, IpPacket.ACK, null, 0, 0)
                extractMessages(s)
            }
        } else if (flags and IpPacket.ACK != 0) {
            // pure ACK: just refresh
            s.theirAck = (p.tcpSeq().toLong() + payloadLen) and 0xFFFFFFFFL
        }
        if (flags and IpPacket.FIN != 0) {
            s.theirAck = (p.tcpSeq().toLong() + payloadLen + 1) and 0xFFFFFFFFL
            send(s, IpPacket.ACK, null, 0, 0)
            send(s, IpPacket.FIN or IpPacket.ACK, null, 0, 0)
            s.mySeq = (s.mySeq + 1) and 0xFFFFFFFFL // FIN consumes one
            sessions.remove(k)
        }
    }

    /** Pull complete length-prefixed DNS messages out of the session buffer. */
    private fun extractMessages(s: Session) {
        while (true) {
            val b = s.buf.toByteArray()
            if (b.size < 2) return
            val msgLen = ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
            if (msgLen <= 0 || msgLen > 4096) {
                // garbage: reset connection
                send(s, IpPacket.RST or IpPacket.ACK, null, 0, 0)
                sessions.remove(key(s.srcIp, s.srcPort))
                return
            }
            if (b.size < 2 + msgLen) return // wait for more data
            val msg = ByteArray(msgLen)
            System.arraycopy(b, 2, msg, 0, msgLen)
            // compact buffer
            s.buf.reset()
            s.buf.write(b, 2 + msgLen, b.size - 2 - msgLen)
            val bypass = if (DnsVpnService.isBypassDns(s.dstIp))
                IpPacket.ipToString(s.dstIp) else ""
            svc.enqueueTcpDns(Task(s, msg, s.uid, s.app, bypass))
        }
    }

    /**
     * Write a length-prefixed DNS response back to the client.
     * Called on the TCP worker thread.
     */
    @Synchronized
    fun respond(s: Session, resp: ByteArray?) {
        if (resp == null || resp.isEmpty() || resp.size > 4096) return
        // verify identity, not just key: a recycled source port could map to a NEW session
        if (sessions[key(s.srcIp, s.srcPort)] !== s) return // gone or replaced
        val framed = ByteArray(2 + resp.size)
        framed[0] = ((resp.size shr 8) and 0xFF).toByte()
        framed[1] = (resp.size and 0xFF).toByte()
        System.arraycopy(resp, 0, framed, 2, resp.size)
        send(s, IpPacket.PSH or IpPacket.ACK, framed, 0, framed.size)
        s.mySeq = (s.mySeq + framed.size) and 0xFFFFFFFFL
    }

    private fun send(s: Session, flags: Int, payload: ByteArray?, off: Int, len: Int) {
        val out = ByteArray(40 + len)
        val total = IpPacket.buildTcp(out, s.dstIp, s.srcIp, 53, s.srcPort,
                s.mySeq, s.theirAck, flags, 65535, payload, off, len)
        svc.writeTun(out, total)
    }

    private fun sendReset(p: IpPacket) {
        val out = ByteArray(40)
        val ack = (p.tcpSeq().toLong() + maxOf(p.tcpPayloadLen(), 0) + 1) and 0xFFFFFFFFL
        val total = IpPacket.buildTcp(out, p.dstIp, p.srcIp, 53, p.tcpSrcPort(),
                0, ack, IpPacket.RST or IpPacket.ACK, 0, null, 0, 0)
        svc.writeTun(out, total)
    }

    private fun cleanup() {
        val now = System.currentTimeMillis()
        val it = sessions.entries.iterator()
        while (it.hasNext()) {
            if (now - it.next().value.lastActive > 120000) it.remove()
        }
    }
}
