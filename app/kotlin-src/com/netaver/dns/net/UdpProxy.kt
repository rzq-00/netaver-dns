package com.netaver.dns.net

import android.util.Log
import com.netaver.dns.DnsVpnService
import com.netaver.dns.log.Entries
import com.netaver.dns.util.AppResolver
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Userspace UDP NAT. One protected DatagramChannel per flow, single
 * selector thread, idle flows reclaimed. Battery-friendly: no polling,
 * wakes only on traffic.
 */
class UdpProxy(private val vpn: DnsVpnService) {

    /** Package-visible in the Java original; `internal` is the module-level equivalent. */
    internal class Session {
        lateinit var channel: DatagramChannel
        var srcIp: Int = 0
        var srcPort: Int = 0
        var dstIp: Int = 0
        var dstPort: Int = 0
        var app: String? = null
        var uid: Int = -1
        var noLog: Boolean = false // LAN passthrough: don't log
        var countryCode: String = ""
        var lastActivity: Long = 0
        var startTime: Long = 0
        var bytesUp: Long = 0
        var bytesDown: Long = 0
    }

    private lateinit var selector: Selector
    private var thread: Thread? = null
    @Volatile private var running = false
    private val sessions = ConcurrentHashMap<Long, Session>()
    private val pendingRegistrations = ConcurrentLinkedQueue<Runnable>()
    private var lastCleanup: Long = 0

    @Throws(IOException::class)
    fun start() {
        selector = Selector.open()
        running = true
        val th = Thread(Runnable { loop() }, "udp-proxy")
        th.isDaemon = true
        thread = th
        th.start()
    }

    fun stop() {
        running = false
        try { if (::selector.isInitialized) selector.wakeup() } catch (_: Exception) {}
        for (e in sessions.entries) closeSession(e.key, e.value, false)
        sessions.clear()
        try { if (::selector.isInitialized) selector.close() } catch (_: Exception) {}
    }

    /**
     * Network change (WiFi switch): drop all UDP sessions so the next
     * packet from the client creates a fresh session via the new network.
     * Unlike stop(), the selector loop keeps running.
     */
    fun resetAllSessions() {
        if (!running) return
        for (e in sessions.entries.toList()) closeSession(e.key, e.value, false)
        sessions.clear()
    }

    /** Called on the TUN reader thread. */
    fun handle(p: IpPacket) {
        if (!running) return
        val srcPort = p.udpSrcPort()
        val dstPort = p.udpDstPort()
        val key = flowKey(p.srcIp, srcPort, p.dstIp, dstPort)
        val s: Session
        val existing = sessions[key]
        if (existing != null) {
            s = existing
        } else {
            val uid = vpn.resolver().uidFor(AppResolver.protoUdp(), p.srcIp, srcPort, p.dstIp, dstPort)
            val lanBypass = vpn.isLanBypass(p.dstIp)
            // (b) compute the destination string once; reused for connect + geo below
            val dstIpStr = IpPacket.ipToString(p.dstIp)
            vpn.debugConnStart(vpn.resolver(), uid, "UDP", "$dstIpStr:$dstPort")
            // ---- firewall (RethinkDNS-style per-app block; skipped for LAN passthrough) ----
            if (!lanBypass && vpn.firewall().isBlocked(uid)) {
                val app = vpn.resolver().labelForUid(uid)
                vpn.logBus().addConn(Entries.ConnEntry(System.currentTimeMillis(),
                        app, uid, "UDP", "$dstIpStr:$dstPort",
                        0, 0, 0, true))
                return // drop silently
            }
            val ns = Session()
            ns.srcIp = p.srcIp
            ns.srcPort = srcPort
            ns.dstIp = p.dstIp
            ns.dstPort = dstPort
            ns.uid = uid
            ns.noLog = lanBypass
            ns.startTime = System.currentTimeMillis()
            ns.lastActivity = ns.startTime
            try {
                val ch = DatagramChannel.open()
                ch.configureBlocking(false)
                vpn.protect(ch.socket())
                ch.connect(InetSocketAddress(dstIpStr, dstPort))
                ns.channel = ch
                ns.app = vpn.resolver().labelForUid(uid)
                ns.countryCode = vpn.geoIp().cached(dstIpStr)
                vpn.geoIp().resolve(dstIpStr)
                sessions[key] = ns
                pendingRegistrations.offer(Runnable {
                    try {
                        ch.register(selector, SelectionKey.OP_READ, ns)
                    } catch (e: Exception) {
                        Log.d(TAG, "register failed", e)
                        // don't leave a blackhole session: drop it so the next
                        // packet creates a fresh one instead of silently stalling
                        sessions.remove(key, ns)
                        try { ch.close() } catch (_: Exception) {}
                    }
                })
                try {
                    selector.wakeup()
                } catch (_: Exception) {
                    // selector died under us (stop() race): tear down the
                    // session we just created instead of leaking its FD
                    sessions.remove(key, ns)
                    try { ch.close() } catch (_: Exception) {}
                    return
                }
            } catch (e: Exception) {
                Log.d(TAG, "udp session create failed", e)
                sessions.remove(key)
                return
            }
            s = ns
        }
        val poff = p.udpPayloadOffset()
        val plen = p.udpPayloadLen()
        if (plen < 0) return
        try {
            val bb = ByteBuffer.wrap(p.buf, poff, plen)
            val n = s.channel.write(bb)
            s.bytesUp += maxOf(0, n)
            s.lastActivity = System.currentTimeMillis()
        } catch (e: IOException) {
            Log.d(TAG, "udp write failed", e)
        }
    }

    private fun loop() {
        val sel = selector
        // M9: a UDP payload can reach 65507 B — the old 2048 B buffers
        // silently truncated large datagrams; payload max + IP/UDP headers
        val readBuf = ByteBuffer.allocate(65536 + 28)
        val outPkt = ByteArray(65536 + 28)
        while (running) {
            try {
                // drain registrations first
                while (true) {
                    val r = pendingRegistrations.poll() ?: break
                    r.run()
                }

                val n = sel.select(SELECT_TIMEOUT_MS)
                val now = System.currentTimeMillis()
                if (n > 0) {
                    val it = sel.selectedKeys().iterator()
                    while (it.hasNext()) {
                        val key = it.next()
                        it.remove()
                        if (!key.isValid || !key.isReadable) continue
                        val s = key.attachment() as Session
                        readBuf.clear()
                        val len = try {
                            s.channel.read(readBuf)
                        } catch (e: IOException) {
                            closeSession(sessionKey(s), s, true)
                            continue
                        }
                        if (len <= 0) continue
                        s.bytesDown += len
                        s.lastActivity = now
                        val total = IpPacket.buildUdp(outPkt, s.dstIp, s.srcIp,
                                s.dstPort, s.srcPort,
                                readBuf.array(), 0, len)
                        vpn.writeTun(outPkt, total)
                    }
                }
                // idle cleanup
                if (now - lastCleanup > IDLE_TIMEOUT_MS) {
                    lastCleanup = now
                    for (e in sessions.entries) {
                        if (now - e.value.lastActivity > IDLE_TIMEOUT_MS) {
                            closeSession(e.key, e.value, true)
                        }
                    }
                }
            } catch (e: Exception) {
                if (running) Log.w(TAG, "udp loop", e)
            }
        }
    }

    // 64-bit key, zero-alloc (srcIp is the constant TUN address)
    private fun sessionKey(s: Session): Long =
        flowKey(s.srcIp, s.srcPort, s.dstIp, s.dstPort)

    private fun flowKey(sIp: Int, sPort: Int, dIp: Int, dPort: Int): Long =
        (dIp.toLong() shl 32) or ((sPort.toLong() and 0xFFFF) shl 16) or (dPort.toLong() and 0xFFFF)

    private fun closeSession(key: Long, s: Session, log: Boolean) {
        sessions.remove(key)
        // drop the cached UID: the ephemeral port may be reused by another app
        try { vpn.resolver().invalidateFlow(AppResolver.protoUdp(),
                s.srcIp, s.srcPort, s.dstIp, s.dstPort) } catch (_: Exception) {}
        try {
            val sk = s.channel.keyFor(selector)
            sk?.cancel()
            s.channel.close()
        } catch (_: Exception) {}
        if (log && !s.noLog && (s.bytesUp > 0 || s.bytesDown > 0)) {
            val e = Entries.ConnEntry(System.currentTimeMillis(),
                    s.app ?: vpn.resolver().labelForUid(s.uid),
                    s.uid, "UDP",
                    IpPacket.ipToString(s.dstIp) + ":" + s.dstPort,
                    s.bytesUp, s.bytesDown, System.currentTimeMillis() - s.startTime, false)
            e.countryCode = if (s.countryCode.isEmpty())
                vpn.geoIp().cached(IpPacket.ipToString(s.dstIp)) else s.countryCode
            vpn.logBus().addConn(e)
        }
    }

    companion object {
        private const val TAG = "UdpProxy"
        private const val IDLE_TIMEOUT_MS = 60_000L
        private const val SELECT_TIMEOUT_MS = 5_000L
    }
}
