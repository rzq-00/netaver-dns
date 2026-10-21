package com.netaver.dns.net

import android.util.Log
import com.netaver.dns.DnsVpnService
import com.netaver.dns.log.Entries
import com.netaver.dns.util.AppResolver
import java.io.IOException
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.Random
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Userspace TCP proxy: terminates the phone-side TCP on the TUN interface
 * and relays to the real destination via a protected SocketChannel.
 * Single selector thread owns all TCB state (no races). Retransmission,
 * FIN handling and idle reclamation included. Battery-friendly: wakes only
 * on traffic, 5s blocking select quantum; retransmit/idle timeouts are
 * checked on every selector wakeup.
 */
class TcpProxy(private val vpn: DnsVpnService) {

    /** Package-visible in the Java original; `internal` is the module-level equivalent. */
    internal class Tcb {
        lateinit var ch: SocketChannel
        var cliIp: Int = 0
        var cliPort: Int = 0
        var srvIp: Int = 0
        var srvPort: Int = 0
        var app: String? = null
        var uid: Int = -1
        var noLog: Boolean = false // LAN passthrough: skip firewall already, don't log either
        var countryCode: String = ""
        var state: Int = 0
        var iss: Int = 0
        var irs: Int = 0
        var sndNxt: Int = 0
        var sndUna: Int = 0
        var rcvNxt: Int = 0
        val unacked: ByteArray = ByteArray(MAX_UNACKED)
        var unackedTime: Long = 0
        var retries: Int = 0
        val writeQueue: java.util.ArrayDeque<ByteBuffer> = java.util.ArrayDeque() // client -> socket remainders, in order
        @Volatile var upBuffered: Int = 0 // bytes in writeQueue (tun thread <-> selector thread)
        @Volatile var upThrottled: Boolean = false // zero window advertised (tun thread <-> selector thread)
        @Volatile var unackedLen: Int = 0 // server->client bytes awaiting client ACK (selector <-> tun thread)
        // offset of the first unacked byte in `unacked` (avoids O(n) memmove per ACK)
        var unackedOff: Int = 0
        @Volatile var readPaused: Boolean = false // OP_READ paused when unacked full (selector -> tun thread)
        var lastActivity: Long = 0
        var startTime: Long = 0
        var finTime: Long = 0
        var bytesUp: Long = 0
        var bytesDown: Long = 0
        var finSent: Boolean = false
    }

    private val random = Random()
    private lateinit var selector: Selector
    private var thread: Thread? = null
    @Volatile private var running = false

    private val tcbs = ConcurrentHashMap<Long, Tcb>()
    private val tunQueue = ConcurrentLinkedQueue<IpPacket>()
    /** Per-thread packet build buffer: buildTcp+writeTun runs on both the tun
     *  thread and the selector thread — a shared buffer corrupted packets. */
    private val outPktLocal = ThreadLocal.withInitial { ByteArray(2048) }
    private fun outPkt(): ByteArray = outPktLocal.get()
    private val readBuf: ByteBuffer = ByteBuffer.allocate(32 * 1024)

    @Throws(IOException::class)
    fun start() {
        selector = Selector.open()
        running = true
        val th = Thread(Runnable { loop() }, "tcp-proxy")
        th.isDaemon = true
        thread = th
        th.start()
    }

    fun stop() {
        running = false
        try { if (::selector.isInitialized) selector.wakeup() } catch (_: Exception) {}
        for (t in tcbs.values) closeTcb(t, true)
        tcbs.clear()
        try { if (::selector.isInitialized) selector.close() } catch (_: Exception) {}
    }

    /** Called on TUN reader thread: just enqueue. */
    fun handle(p: IpPacket) {
        if (!running) return
        tunQueue.offer(p)
        selector.wakeup()
    }

    /** Send RST for a packet (used for blocked ports). Called on TUN thread. */
    fun reset(p: IpPacket) {
        if (p.protocol != IpPacket.PROTO_TCP) return
        val flags = p.tcpFlags()
        if ((flags and IpPacket.RST) != 0) return
        val ack = p.tcpSeq() + p.tcpPayloadLen() + (if ((flags and IpPacket.SYN) != 0) 1 else 0) +
                (if ((flags and IpPacket.FIN) != 0) 1 else 0)
        val total = IpPacket.buildTcp(outPkt(), p.dstIp, p.srcIp, p.tcpDstPort(), p.tcpSrcPort(),
                0, ack, IpPacket.RST or IpPacket.ACK, 0, null, 0, 0)
        vpn.writeTun(outPkt(), total)
    }

    // 64-bit key, zero-alloc. srcIp is always the TUN address (10.8.0.2/32),
    // so dstIp(32)+srcPort(16)+dstPort(16) is collision-free.
    private fun key(sIp: Int, sPort: Int, dIp: Int, dPort: Int): Long =
        (dIp.toLong() shl 32) or ((sPort.toLong() and 0xFFFF) shl 16) or (dPort.toLong() and 0xFFFF)

    private fun loop() {
        val sel = selector
        var lastHousekeeping = 0L
        while (running) {
            try {
                while (true) {
                    val p = tunQueue.poll() ?: break
                    processTun(p)
                }

                val n = sel.select(SELECT_MS)
                val now = System.currentTimeMillis()
                if (n > 0) {
                    val it = sel.selectedKeys().iterator()
                    while (it.hasNext()) {
                        val k = it.next()
                        it.remove()
                        if (!k.isValid) continue
                        val t = k.attachment() as Tcb
                        try {
                            if (k.isConnectable) onConnect(k, t)
                            if (k.isValid && k.isReadable) onSocketRead(k, t)
                            if (k.isValid && k.isWritable) onSocketWrite(k, t)
                        } catch (e: Exception) {
                            Log.d(TAG, "io", e)
                            resetAndClose(t)
                        }
                    }
                }
                // (c) timeouts / idle cleanup — throttled to 1/s. Running it on
                // every wakeup is O(connections) per packet during bulk transfer.
                if (now - lastHousekeeping >= 1000) {
                    lastHousekeeping = now
                    housekeeping(now)
                }
            } catch (e: Exception) {
                if (running) Log.w(TAG, "tcp loop", e)
            }
        }
    }

    // ---------------- TUN -> us ----------------

    private fun processTun(p: IpPacket) {
        if (p.protocol != IpPacket.PROTO_TCP) return
        val k = key(p.srcIp, p.tcpSrcPort(), p.dstIp, p.tcpDstPort())
        val t = tcbs[k]
        val flags = p.tcpFlags()

        if (t == null) {
            if ((flags and IpPacket.SYN) != 0 && (flags and IpPacket.ACK) == 0) {
                newConnection(p, k)
            } else if ((flags and IpPacket.RST) == 0) {
                // unknown flow: RST
                val ack = p.tcpSeq() + p.tcpPayloadLen() +
                        (if ((flags and IpPacket.SYN) != 0) 1 else 0) +
                        (if ((flags and IpPacket.FIN) != 0) 1 else 0)
                sendTcp(p.dstIp, p.srcIp, p.tcpDstPort(), p.tcpSrcPort(),
                        0, ack, IpPacket.RST or IpPacket.ACK, null, 0, 0)
            }
            return
        }

        t.lastActivity = System.currentTimeMillis()
        if ((flags and IpPacket.RST) != 0) {
            closeTcb(t, false)
            return
        }
        if (t.state == S_LAST_ACK) {
            // absorb final ACKs; resend FIN on timeout via housekeeping
            // (unsigned compare: sndNxt may hold a negative Int for seq > 2^31)
            val ack = p.tcpAck()
            if (ack == (t.sndNxt.toLong() and 0xFFFFFFFFL)) closeTcb(t, true)
            return
        }
        if (t.state != S_ESTABLISHED) return // CONNECTING: ignore client retransmits

        // ACK processing (advances sndUna)
        if ((flags and IpPacket.ACK) != 0) {
            val acked = (p.tcpAck() - (t.sndUna.toLong() and 0xFFFFFFFFL)).toInt()
            if (acked > 0 && acked <= t.unackedLen) {
                // offset-based trim: O(1), no memmove (compaction happens on append)
                t.unackedOff += acked
                t.unackedLen -= acked
                t.sndUna += acked
                t.retries = 0
                t.unackedTime = System.currentTimeMillis()
                // resume socket reads if we paused them for download backpressure
                if (t.readPaused && t.unackedLen < MAX_UNACKED) {
                    t.readPaused = false
                    try {
                        val sk = t.ch.keyFor(selector)
                        if (sk != null && sk.isValid) {
                            sk.interestOps(sk.interestOps() or SelectionKey.OP_READ)
                            selector.wakeup()
                        }
                    } catch (_: Exception) { }
                }
            }
        }

        val payloadLen = p.tcpPayloadLen()
        if (payloadLen > 0) {
            val seq = p.tcpSeq()
            if (seq == (t.rcvNxt.toLong() and 0xFFFFFFFFL)) {
                // in-order: forward to WAN socket.
                // All writeQueue/socket access is serialized under the Tcb lock:
                // processTun runs on the tun thread while onSocketWrite runs on
                // the selector thread, and ArrayDeque is NOT thread-safe —
                // concurrent access corrupted the queue (lost segments), which
                // made bulk uploads stall forever. Direct socket writes also go
                // under the lock so segments can't interleave out of order.
                val poff = p.tcpPayloadOffset()
                val src = ByteBuffer.wrap(p.buf, poff, payloadLen)
                var dropped = false
                var queued = false
                synchronized(t) {
                    if (!t.writeQueue.isEmpty()) {
                        // selector is draining: append strictly in order
                        if (t.upBuffered + payloadLen > UP_BUF_MAX) {
                            dropped = true
                        } else {
                            val pend = ByteBuffer.allocate(payloadLen)
                            pend.put(src)
                            pend.flip()
                            t.writeQueue.addLast(pend)
                            t.upBuffered += payloadLen
                            queued = true
                        }
                    } else {
                        try {
                            val wrote = t.ch.write(src)
                            t.bytesUp += maxOf(0, wrote)
                            if (src.hasRemaining()) {
                                if (t.upBuffered + src.remaining() > UP_BUF_MAX) {
                                    dropped = true
                                } else {
                                    // queue remainder IN ORDER (never overwrite pending data)
                                    val pend = ByteBuffer.allocate(src.remaining())
                                    pend.put(src)
                                    pend.flip()
                                    t.writeQueue.addLast(pend)
                                    t.upBuffered += pend.remaining()
                                    queued = true
                                }
                            }
                        } catch (_: IOException) {
                            resetAndClose(t)
                            return
                        }
                    }
                    if (!dropped) {
                        t.rcvNxt += payloadLen
                        // backpressure: throttle the client when our upload buffer fills
                        if (!t.upThrottled && t.upBuffered >= UP_BUF_HIGH) {
                            t.upThrottled = true
                        }
                    }
                }
                if (dropped) {
                    // pathological: client ignores zero window; drop, keep it simple
                    sendTcpW(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                            t.sndNxt.toLong(), t.rcvNxt.toLong(), IpPacket.ACK, null, 0, 0, 0)
                    return
                }
                if (queued) requestWrite(t)
                sendTcpW(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                        t.sndNxt.toLong(), t.rcvNxt.toLong(), IpPacket.ACK, null, 0, 0, advWindow(t))
            } else {
                // out-of-order: duplicate ACK
                sendTcpW(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                        t.sndNxt.toLong(), t.rcvNxt.toLong(), IpPacket.ACK, null, 0, 0, advWindow(t))
            }
        }

        if ((flags and IpPacket.FIN) != 0) {
            t.rcvNxt++ // consume FIN
            // ACK the FIN and send our FIN
            sendFin(t)
        }
    }

    private fun newConnection(p: IpPacket, k: Long) {
        val uid = vpn.resolver().uidFor(AppResolver.protoTcp(),
                p.srcIp, p.tcpSrcPort(), p.dstIp, p.tcpDstPort())
        val lanBypass = vpn.isLanBypass(p.dstIp)
        // (b) compute the destination string once; reused below for geo lookup
        val srvIpStr = IpPacket.ipToString(p.dstIp)
        vpn.debugConnStart(vpn.resolver().labelForUid(uid), "TCP",
                "$srvIpStr:${p.tcpDstPort()}")
        // ---- firewall (RethinkDNS-style per-app block; skipped for LAN passthrough) ----
        if (!lanBypass && vpn.firewall().isBlocked(uid)) {
            val app = vpn.resolver().labelForUid(uid)
            val dest = "$srvIpStr:${p.tcpDstPort()}"
            vpn.logBus().addConn(Entries.ConnEntry(System.currentTimeMillis(),
                    app, uid, "TCP", dest, 0, 0, 0, true))
            sendTcp(p.dstIp, p.srcIp, p.tcpDstPort(), p.tcpSrcPort(),
                    0, p.tcpSeq() + 1, IpPacket.RST or IpPacket.ACK, null, 0, 0)
            return
        }
        val t = Tcb()
        t.cliIp = p.srcIp
        t.cliPort = p.tcpSrcPort()
        t.srvIp = p.dstIp
        t.srvPort = p.tcpDstPort()
        t.uid = uid
        t.noLog = lanBypass
        t.irs = p.tcpSeq().toInt()
        t.rcvNxt = t.irs + 1
        t.iss = random.nextInt()
        t.sndNxt = t.iss + 1 // SYN consumes one
        t.sndUna = t.iss + 1
        t.state = S_CONNECTING
        t.startTime = System.currentTimeMillis()
        t.lastActivity = t.startTime
        try {
            val ch = SocketChannel.open()
            ch.configureBlocking(false)
            ch.setOption(StandardSocketOptions.TCP_NODELAY, true)
            vpn.protect(ch.socket())
            t.ch = ch
            t.app = vpn.resolver().labelForUid(uid)
            // kick off country resolution for the log (cached after first hit)
            t.countryCode = vpn.geoIp().cached(srvIpStr)
            vpn.geoIp().resolve(srvIpStr)
            tcbs[k] = t
            val done = ch.connect(InetSocketAddress(srvIpStr, p.tcpDstPort()))
            ch.register(selector, if (done) SelectionKey.OP_READ else SelectionKey.OP_CONNECT, t)
            // register() from the tun thread: wake the selector so OP_CONNECT
            // is noticed immediately instead of at the next 5s select timeout
            selector.wakeup()
            if (done) onConnect(ch.keyFor(selector), t)
        } catch (e: Exception) {
            Log.d(TAG, "connect failed", e)
            tcbs.remove(k)
            try { t.ch.close() } catch (_: Exception) {}
            sendTcp(p.dstIp, p.srcIp, p.tcpDstPort(), p.tcpSrcPort(),
                    0, t.rcvNxt.toLong(), IpPacket.RST or IpPacket.ACK, null, 0, 0)
        }
    }

    // ---------------- socket events ----------------

    private fun onConnect(k: SelectionKey, t: Tcb) {
        if (t.ch.finishConnect()) {
            t.state = S_ESTABLISHED
            t.lastActivity = System.currentTimeMillis()
            k.interestOps(SelectionKey.OP_READ)
            // SYN+ACK to client
            sendTcp(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                    t.iss.toLong(), t.rcvNxt.toLong(), IpPacket.SYN or IpPacket.ACK, null, 0, 0)
        }
    }

    private fun onSocketRead(k: SelectionKey, t: Tcb) {
        if (t.state != S_ESTABLISHED) return
        // Download backpressure: never read more than the unacked buffer can hold.
        // Pausing OP_READ (instead of dropping already-read data) avoids forced
        // server retransmissions, which showed up as ~2x bytes vs the speed test.
        val avail = MAX_UNACKED - t.unackedLen
        if (avail <= 0) {
            t.readPaused = true
            k.interestOps(k.interestOps() and SelectionKey.OP_READ.inv())
            return
        }
        readBuf.clear()
        readBuf.limit(minOf(readBuf.capacity(), avail))
        val n = t.ch.read(readBuf)
        t.lastActivity = System.currentTimeMillis()
        if (n == -1) {
            sendFin(t) // server closed: FIN to client
            return
        }
        if (n == 0) return
        t.bytesDown += n
        // segmentize to client (n <= avail, so everything fits in unacked)
        var off = 0
        while (off < n) {
            val chunk = minOf(SEG, n - off)
            sendData(t, readBuf.array(), off, chunk)
            off += chunk
        }
    }

    /** Ask the selector thread to drain a Tcb's write queue (safe from any thread). */
    private fun requestWrite(t: Tcb) {
        try {
            val sk = t.ch.keyFor(selector)
            if (sk != null && sk.isValid) {
                sk.interestOps(sk.interestOps() or SelectionKey.OP_WRITE)
                selector.wakeup()
            }
        } catch (_: Exception) { }
    }

    private fun onSocketWrite(k: SelectionKey, t: Tcb) {
        var sendWindowUpdate = false
        synchronized(t) {
            val wasThrottled = t.upThrottled
            while (!t.writeQueue.isEmpty()) {
                val b = t.writeQueue.peekFirst()
                val rem = b.remaining()
                t.ch.write(b)
                val wroteNow = rem - b.remaining()
                t.upBuffered -= wroteNow
                t.bytesUp += wroteNow
                if (b.hasRemaining()) break // socket full again
                t.writeQueue.pollFirst()
            }
            if (t.writeQueue.isEmpty()) {
                k.interestOps(k.interestOps() and SelectionKey.OP_WRITE.inv())
            }
            // re-open the receive window once drained enough
            if (wasThrottled && t.upBuffered < UP_BUF_LOW) {
                t.upThrottled = false
                sendWindowUpdate = true
            }
        }
        if (sendWindowUpdate) {
            sendTcpW(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                    t.sndNxt.toLong(), t.rcvNxt.toLong(), IpPacket.ACK, null, 0, 0, ADV_WINDOW)
        }
    }

    // ---------------- sending ----------------

    /** Receive window to advertise to the client (upload backpressure). */
    private fun advWindow(t: Tcb): Int =
        if (t.upThrottled) 0 else ADV_WINDOW

    /** Send data segment to client; tracks for retransmission. */
    private fun sendData(t: Tcb, data: ByteArray, off: Int, len: Int) {
        // compact once if the tail doesn't fit (amortized; no per-ACK memmove)
        if (t.unackedOff + t.unackedLen + len > MAX_UNACKED) {
            if (t.unackedLen > 0) System.arraycopy(t.unacked, t.unackedOff, t.unacked, 0, t.unackedLen)
            t.unackedOff = 0
        }
        System.arraycopy(data, off, t.unacked, t.unackedOff + t.unackedLen, len)
        val total = IpPacket.buildTcp(outPkt(), t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                t.sndNxt.toLong() and 0xFFFFFFFFL, t.rcvNxt.toLong() and 0xFFFFFFFFL,
                IpPacket.PSH or IpPacket.ACK, advWindow(t), data, off, len)
        vpn.writeTun(outPkt(), total)
        t.sndNxt += len
        t.unackedLen += len
        if (t.unackedLen == len) t.unackedTime = System.currentTimeMillis()
    }

    private fun sendTcp(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
                        seq: Long, ack: Long, flags: Int, pl: ByteArray?, poff: Int, plen: Int) {
        sendTcpW(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, pl, poff, plen, ADV_WINDOW)
    }

    private fun sendTcpW(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
                         seq: Long, ack: Long, flags: Int, pl: ByteArray?, poff: Int, plen: Int, window: Int) {
        val total = IpPacket.buildTcp(outPkt(), srcIp, dstIp, srcPort, dstPort,
                seq, ack, flags, window, pl, poff, plen)
        vpn.writeTun(outPkt(), total)
    }

    private fun sendFin(t: Tcb) {
        if (t.finSent) return
        t.finSent = true
        try { t.ch.shutdownOutput() } catch (_: Exception) {}
        sendTcp(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                t.sndNxt.toLong() and 0xFFFFFFFFL, t.rcvNxt.toLong() and 0xFFFFFFFFL,
                IpPacket.FIN or IpPacket.ACK, null, 0, 0)
        t.sndNxt++ // FIN consumes a sequence number
        t.state = S_LAST_ACK
        t.finTime = System.currentTimeMillis()
    }

    // ---------------- timers ----------------

    private fun housekeeping(now: Long) {
        for ((_, t) in tcbs) {
            if (t.state == S_ESTABLISHED && t.unackedLen > 0
                    && now - t.unackedTime > RTO_MS) {
                if (t.retries >= MAX_RETRIES) {
                    resetAndClose(t)
                    continue
                }
                // retransmit unacked (one segment at a time, like real TCP;
                // never more than fits the packet buffer)
                val rlen = minOf(t.unackedLen, SEG)
                val total = IpPacket.buildTcp(outPkt(), t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                        t.sndUna.toLong() and 0xFFFFFFFFL, t.rcvNxt.toLong() and 0xFFFFFFFFL,
                        IpPacket.PSH or IpPacket.ACK, 65535, t.unacked, t.unackedOff, rlen)
                vpn.writeTun(outPkt(), total)
                t.unackedTime = now
                t.retries++
            }
            if (t.state == S_LAST_ACK && now - t.finTime > 5000) {
                closeTcb(t, true)
                continue
            }
            if (now - t.lastActivity > IDLE_MS) {
                resetAndClose(t)
            }
        }
    }

    private fun resetAndClose(t: Tcb) {
        sendTcp(t.srvIp, t.cliIp, t.srvPort, t.cliPort,
                t.sndNxt.toLong() and 0xFFFFFFFFL, t.rcvNxt.toLong() and 0xFFFFFFFFL,
                IpPacket.RST or IpPacket.ACK, null, 0, 0)
        closeTcb(t, false)
    }

    private fun closeTcb(t: Tcb, graceful: Boolean) {
        val k = key(t.cliIp, t.cliPort, t.srvIp, t.srvPort)
        tcbs.remove(k)
        // drop the cached UID: the ephemeral port may be reused by another app
        try { vpn.resolver().invalidateFlow(AppResolver.protoTcp(),
                t.cliIp, t.cliPort, t.srvIp, t.srvPort) } catch (_: Exception) {}
        try {
            val sk = t.ch.keyFor(selector)
            sk?.cancel()
            t.ch.close()
        } catch (_: Exception) {}
        if (!t.noLog && (t.bytesUp > 0 || t.bytesDown > 0)) {
            val app = t.app ?: vpn.resolver().labelForUid(t.uid)
            val e = Entries.ConnEntry(System.currentTimeMillis(), app, t.uid, "TCP",
                    IpPacket.ipToString(t.srvIp) + ":" + t.srvPort,
                    t.bytesUp, t.bytesDown, System.currentTimeMillis() - t.startTime, false)
            e.countryCode = if (t.countryCode.isEmpty())
                vpn.geoIp().cached(IpPacket.ipToString(t.srvIp)) else t.countryCode
            vpn.logBus().addConn(e)
        }
    }

    companion object {
        private const val TAG = "TcpProxy"
        // (c) was 500: longer blocking select; retransmit/idle timeouts are
        // checked on every selector wakeup instead of every 500ms.
        private const val SELECT_MS = 5000L
        private const val IDLE_MS = 120_000L
        private const val RTO_MS = 1000L
        private const val MAX_RETRIES = 5
        private const val MAX_UNACKED = 32 * 1024
        private const val SEG = 1460

        private const val S_CONNECTING = 1
        private const val S_ESTABLISHED = 2
        private const val S_LAST_ACK = 3

        // Upload flow control: cap client->server buffering so the client can't
        // outrun the real uplink (which inflated speedtest uploads + ballooned RAM).
        private const val UP_BUF_HIGH = 512 * 1024 // advertise zero window above this
        private const val UP_BUF_LOW = 128 * 1024 // re-open window below this
        private const val UP_BUF_MAX = 4 * 1024 * 1024 // hard drop above this (rude client)
        private const val ADV_WINDOW = 65535
    }
}
