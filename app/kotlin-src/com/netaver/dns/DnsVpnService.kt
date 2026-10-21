package com.netaver.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import com.netaver.dns.dns.BlocklistManager
import com.netaver.dns.dns.DnsMessage
import com.netaver.dns.dns.DnsUpstream
import com.netaver.dns.dns.DohUpstream
import com.netaver.dns.dns.DotUpstream
import com.netaver.dns.dns.PlainUpstream
import com.netaver.dns.dns.TcpDns
import com.netaver.dns.log.Entries
import com.netaver.dns.log.LogBus
import com.netaver.dns.net.GeoIp
import com.netaver.dns.net.Ip6Reject
import com.netaver.dns.net.IpPacket
import com.netaver.dns.net.TcpProxy
import com.netaver.dns.net.UdpProxy
import com.netaver.dns.ui.MainActivity
import com.netaver.dns.util.AppResolver
import com.netaver.dns.util.FirewallManager
import com.netaver.dns.util.Prefs
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.HashMap
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * VpnService that intercepts DNS (port 53), filters via blocklists,
 * and forwards everything else. Battery-friendly: event-driven, no polling,
 * cached UID lookups, in-memory logs.
 *
 * Kotlin port of DnsVpnService.java — behavior identical, same thread model
 * (tunLoop, 4 dnsWorkers, tcpDnsLoop, 60s probe thread, NetworkCallback).
 * No coroutines.
 */
class DnsVpnService : VpnService() {

    companion object {
        private const val TAG = "DnsVpnService"
        const val ACTION_START = "com.netaver.dns.START"
        const val ACTION_STOP = "com.netaver.dns.STOP"

        /** The DNS server we advertise to apps; anything else on port 53 = hardcoded bypass attempt. */
        const val OUR_DNS_IP = (10 shl 24) or (8 shl 16) or (0 shl 8) or 1 // 10.8.0.1
        @JvmStatic
        fun isBypassDns(dstIp: Int): Boolean = dstIp != OUR_DNS_IP

        /** RFC1918 + link-local. */
        @JvmStatic
        fun isLan(ip: Int): Boolean {
            val b0 = (ip ushr 24) and 0xFF
            val b1 = (ip ushr 16) and 0xFF
            if (b0 == 10) return true
            if (b0 == 172) return b1 in 16..31
            if (b0 == 192) return b1 == 168
            if (b0 == 169) return b1 == 254
            return false
        }

        /** Failover: 3 consecutive upstream failures -> mark that target down. */
        private const val FAILOVER_THRESHOLD = 3
        private const val PROBE_INTERVAL_MS = 60_000L
        /** While the VPN stays on: re-check blocklists once this long after the last check. */
        private const val DAILY_LIST_CHECK_MS = 24L * 60 * 60 * 1000
        /** Max wait for the parallel race: first valid response wins. */
        private const val RACE_TIMEOUT_MS = 3_000L
        /** Minimal DNS query (example.com A) used to probe primary recovery. */
        private val PROBE_QUERY = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01
        )

        /**
         * Read by UI (HomeFragment ticker) — no service binding needed.
         * @JvmField (not @JvmStatic): keeps the exact `public static volatile`
         * field shape so the still-Java callers keep compiling unchanged.
         */
        @Volatile
        @JvmField
        var upstreamStatusLine = ""

        /** True while the VPN is up. Read by the Quick Settings tile (VpnTileService). */
        @Volatile
        @JvmField
        var vpnActive = false

        const val CHANNEL_ID = "sunraku_vpn"
        private const val NOTIF_ID = 1
        const val NOTIF_ID_START = 2
        const val ACTION_STOP_VPN = "com.netaver.dns.STOP_VPN"
        const val ACTION_START_VPN = "com.netaver.dns.START_VPN"
        private const val DNS_WORKERS = 4

        // auto-reconnect on network change
        @Volatile
        @JvmField
        var networkLost = false // offline mode: no underlying internet

        /** EMA of real upstream query latency (passive, zero extra traffic). -1 = no data yet. */
        @Volatile
        @JvmField
        var dnsLatencyEmaMs = -1L
        @Volatile
        @JvmField
        var dnsLatencyEmaAt = 0L

        /** Feed the passive latency EMA (called for real upstream queries only). */
        private fun updateLatencyEma(ms: Long) {
            if (dnsLatencyEmaMs < 0) dnsLatencyEmaMs = ms
            else dnsLatencyEmaMs = (dnsLatencyEmaMs * 3 + ms) / 4
            dnsLatencyEmaAt = System.currentTimeMillis()
        }
    }

    @Volatile
    private var running = false
    private var tun: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private val tunLock = Object()

    private var readerThread: Thread? = null
    private var dnsWorkers: Array<Thread>? = null
    private var tcpDnsWorker: Thread? = null
    private lateinit var dnsQueue: BlockingQueue<ByteArray>
    private lateinit var tcpDnsQueue: BlockingQueue<TcpDns.Task>
    private var tcpProxy: TcpProxy? = null
    private var udpProxy: UdpProxy? = null
    private var tcpDns: TcpDns? = null

    private lateinit var prefs: Prefs
    private lateinit var logBus: LogBus
    private lateinit var blocklists: BlocklistManager
    private lateinit var resolver: AppResolver

    private lateinit var mainHandler: Handler
    private var startTime = 0L
    private val notifUpdatePending = AtomicBoolean(false)
    private var geoListener: GeoIp.Listener? = null

    // auto-reconnect on network change
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val netEpoch = AtomicLong(0)

    // throttle for bypass-attempt logging: key -> last log time (avoid spam)
    private val bypassThrottle = HashMap<String, Long>()

    // multi-upstream state (AdGuard Home style; shared by all DNS workers)
    // Battery design: persistent connections per upstream (no TLS handshake per
    // query), blocking threads only (no busy loops), probe thread revives dead
    // upstreams ONLY (never scans healthy ones).
    private val upstreamFails = ConcurrentHashMap<String, AtomicInteger>() // fp -> consec fails
    private val upstreamDown = ConcurrentHashMap<String, Boolean>() // fp -> true when marked down
    private val upstreamEma = ConcurrentHashMap<String, Long>() // fp -> latency EMA ms (fastest mode)
    private val connMap = ConcurrentHashMap<String, DnsUpstream>() // fp -> persistent connection
    private val connLocks = ConcurrentHashMap<String, Any>() // fp -> lock (one query at a time per conn)
    private var raceExec: ExecutorService? = null // parallel-mode fan-out (I/O-blocked threads)
    private var probeThread: Thread? = null
    @Volatile
    private var cfgFp = "" // fingerprint of active upstream config (mode+specs+netEpoch)

    /** Resolved upstream: protocol, connect IP, TLS hostname, DoH path. */
    private class UpstreamTarget {
        var proto = 0       // 0=plain 1=DoT 2=DoH
        var ip = ""         // literal IP to connect to
        var tlsHost = ""    // SNI / Host header
        var dohPath = "/dns-query"
        var port = 0        // connect port
        var label = ""      // for logs/UI
    }

    /** Shared DNS filter logic. Returns null on malformed query. */
    private class DnsResult {
        var resp: ByteArray? = null
        var blocked = false
        var bypass = false // query sent to a hardcoded DNS, not 10.8.0.1
        var upstreamHit = false // true only if an actual upstream query was attempted
        var qname = ""
        var qtype = 0
        var resolvedIp = ""
        var latencyMs = 0L
        var matchInfo = ""
    }

    override fun onCreate() {
        super.onCreate()
        VpnToggleReceiver.cancelStartNotification(this)
        val app = application as NetAverApp
        prefs = app.prefs()
        logBus = app.logBus()
        blocklists = app.blocklists()
        resolver = app.resolver()
        mainHandler = Handler(Looper.getMainLooper())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null && ACTION_STOP == intent.action) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (running) return START_STICKY
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        try {
            val b = Builder()
            b.setSession("NetAver DNS")
            b.addAddress("10.8.0.2", 32)
            b.addAddress("fd00:1::2", 64)
            b.addRoute("0.0.0.0", 0)
            b.addRoute("::", 0) // capture IPv6 too -> dropped (no leak via IPv6 DNS)
            b.addDnsServer("10.8.0.1")
            b.setMtu(1500)
            // Our own traffic (blocklist downloads, GeoIP) bypasses the VPN:
            // more reliable + avoids routing our downloads through the userspace TCP proxy.
            try {
                b.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication failed", e)
            }
            // Split tunnel: user-selected apps bypass the VPN entirely (direct connection,
            // no filtering/DNS/logs for them). Takes effect on (re)establish.
            for (pkg in prefs.splitBypassSet()) {
                try {
                    b.addDisallowedApplication(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "split bypass failed: $pkg", e)
                }
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            tun = b.establish()
            if (tun == null) {
                Log.e(TAG, "establish() returned null")
                stopSelf()
                return
            }
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            stopSelf()
            return
        }

        running = true
        vpnActive = true
        VpnTileService.requestRefresh(this)
        startTime = System.currentTimeMillis()
        tunOut = FileOutputStream(tun!!.fileDescriptor)
        resolver.clear()

        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification())

        // Blocklists: disk cache loads instantly; conditional re-check in
        // background at most once/hour on VPN start (304 = nothing downloaded).
        // Auto-update is always on (no user toggle since v2.2.8).
        Thread({
            try {
                if (blocklists.shouldAutoCheck()) {
                    blocklists.refreshCustomLists()
                } else {
                    blocklists.loadBundled()
                }
            } catch (e: Exception) {
                Log.w(TAG, "list load failed", e)
            }
        }, "bl-refresh").start()

        try {
            tcpProxy = TcpProxy(this)
            udpProxy = UdpProxy(this)
            tcpProxy!!.start()
            udpProxy!!.start()
        } catch (e: IOException) {
            Log.e(TAG, "proxy start failed", e)
            stopVpn()
            return
        }

        dnsQueue = ArrayBlockingQueue(256)
        dnsWorkers = Array(DNS_WORKERS) { i ->
            Thread(this::dnsLoop, "dns-$i").also { it.isDaemon = true; it.start() }
        }

        // TCP DNS (port 53) has its own single worker: low volume, avoids
        // upstream concurrency issues.
        tcpDns = TcpDns(this)
        tcpDnsQueue = ArrayBlockingQueue(64)
        tcpDnsWorker = Thread(this::tcpDnsLoop, "dns-tcp").also { it.isDaemon = true; it.start() }

        readerThread = Thread(this::tunLoop, "tun-reader").also { it.isDaemon = true; it.start() }

        // live-update country flags in DNS + connection logs as GeoIp resolves
        val gl = GeoIp.Listener { ip, cc ->
            logBus.updateDnsCountry(ip, cc)
            logBus.updateConnCountry(ip, cc)
        }
        geoListener = gl
        (application as NetAverApp).geoIp().addListener(gl)

        // auto-reconnect: watch network, flush DNS state when it comes back
        registerNetworkCallback()

        // multi-upstream: migrate legacy single-upstream prefs once, then reset
        // health state and start the revive-probe thread (probes DOWN ones only)
        (application as NetAverApp).prefs().migrateUpstreamsIfNeeded()
        upstreamFails.clear()
        upstreamDown.clear()
        upstreamEma.clear()
        closeAllConns()
        raceExec = Executors.newFixedThreadPool(6)
        updateUpstreamStatus()
        startProbeThread()

        scheduleNotifUpdate()
        Log.i(TAG, "NetAver DNS started")
    }

    /** Reconnect logic: on network return, flush DNS caches and force fresh upstreams. */
    private fun registerNetworkCallback() {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                networkLost = true
                Log.i(TAG, "network lost")
                debugEvent("net_lost", "underlying network lost; offline mode on")
                // Kill pooled upstream sockets NOW: in-flight queries on
                // them fail instantly instead of hanging until the race
                // timeout. Failure streaks from the forced close are
                // cleared again on reconnect (onNetworkReconnected).
                closeAllConns()
                updateNotificationNow()
            }

            override fun onAvailable(network: Network) {
                if (networkLost) {
                    networkLost = false
                    onNetworkReconnected()
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "register network callback failed", e)
            networkCallback = null
        }
    }

    fun debugEvent(tag: String, detail: String) {
        try {
            val app = application as NetAverApp
            app.debugCapture().event(tag, detail)
        } catch (ignored: Exception) {
        }
    }

    /** Log a connection start for debug capture (hangs become visible). */
    fun debugConnStart(appLabel: String, proto: String, dest: String) {
        try {
            val app = application as NetAverApp
            app.debugCapture().connStart(appLabel, proto, dest)
        } catch (ignored: Exception) {
        }
    }

    private fun onNetworkReconnected() {
        Log.i(TAG, "network reconnected: flushing DNS state")
        debugEvent("net_reconnect", "network available again; DNS state flushed")
        updateNotificationNow()
        // DNS flush: drop bootstrap-resolved upstream IPs, DNS cache,
        // stale UID mappings, and force upstream connections to be recreated.
        synchronized(bootstrapCache) { bootstrapCache.clear() }
        (application as NetAverApp).dnsCache().clear()
        resolver.clear()
        netEpoch.incrementAndGet()
        // network change may have fixed dead upstreams: clear their failure
        // streaks so they are retried (probe thread also revives them)
        upstreamFails.clear()
        upstreamDown.clear()
        closeAllConns()
        updateUpstreamStatus()
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        try {
            val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
        } catch (e: Exception) {
            Log.w(TAG, "unregister network callback failed", e)
        }
        networkCallback = null
    }

    private fun stopVpn() {
        running = false
        vpnActive = false
        VpnTileService.requestRefresh(this)
        unregisterNetworkCallback()
        try {
            val gl = geoListener
            if (gl != null) {
                (application as NetAverApp).geoIp().removeListener(gl)
                geoListener = null
            }
            readerThread?.interrupt()
            tcpProxy?.stop()
            udpProxy?.stop()
            dnsWorkers?.forEach { it.interrupt() }
            tcpDnsWorker?.interrupt()
            probeThread?.interrupt()
            try { raceExec?.shutdownNow() } catch (ignored: Exception) { }
            raceExec = null
            closeAllConns()
            tun?.close()
        } catch (e: Exception) {
            Log.w(TAG, "stop error", e)
        } finally {
            tun = null
        }
        stopForeground(true)
        stopSelf()
        Log.i(TAG, "NetAver DNS stopped")
    }

    override fun onDestroy() {
        (application as? NetAverApp)?.logBus()?.flushTotals()
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    // ---------------- TUN ----------------

    private fun tunLoop() {
        val buf = ByteArray(2048)
        val fd = tun?.fileDescriptor ?: return
        try {
            FileInputStream(fd).use { input ->
                while (running) {
                    val len = try {
                        input.read(buf)
                    } catch (e: IOException) {
                        if (running) Log.w(TAG, "tun read", e)
                        break
                    }
                    if (len <= 0) continue
                    val ver = (buf[0].toInt() shr 4) and 0xF
                    if (ver == 6) {
                        // IPv6 "No": reject fast so apps fall back to IPv4
                        Ip6Reject.maybeReject(this, buf, len)
                        continue
                    }
                    // OPTIMASI (a): single parse. IpPacket.parse is zero-copy (views over
                    // the TUN buffer) and dnsQueue/TcpProxy consume p.buf asynchronously,
                    // so the reused read buffer must not escape: copy `len` bytes to a
                    // private per-packet array first, then parse exactly once.
                    // IpPacket.len = min(ipTotalLen, len), so parsing the len-byte copy
                    // yields byte-identical fields to the old parse-copy-parse sequence.
                    val p = IpPacket.parse(buf.copyOf(len), len) ?: continue
                    dispatch(p)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "tun loop ended", e)
        }
    }

    private fun dispatch(p: IpPacket) {
        val lanBypass = isLanBypass(p.dstIp)
        if (p.protocol == IpPacket.PROTO_UDP) {
            val dport = p.udpDstPort()
            if (dport == 53 && !lanBypass) {
                if (!dnsQueue.offer(p.buf)) {
                    Log.d(TAG, "dns queue full, dropping")
                }
                return
            }
            if (dport == 853 && prefs.blockBypass() && !lanBypass) {
                logBypassAttempt(p, false) // block DoT bypass
                return
            }
            udpProxy?.handle(p)
        } else if (p.protocol == IpPacket.PROTO_TCP) {
            if (p.tcpDstPort() == 53 && !lanBypass) {
                // DNS-over-TCP: terminate locally so it can't bypass the filter
                tcpDns?.handle(p)
                return
            }
            if (p.tcpDstPort() == 853 && prefs.blockBypass() && !lanBypass) {
                tcpProxy?.reset(p) // block DoT bypass
                logBypassAttempt(p, true)
                return
            }
            tcpProxy?.handle(p)
        }
        // ICMP & others: dropped in v1 (no ping through VPN; acceptable)
    }

    /** Thread-safe TUN write. */
    fun writeTun(buf: ByteArray, len: Int) {
        synchronized(tunLock) {
            if (!running || tunOut == null) return
            try {
                tunOut!!.write(buf, 0, len)
            } catch (e: IOException) {
                Log.d(TAG, "tun write failed", e)
            }
        }
    }

    fun prefs(): Prefs = prefs
    fun logBus(): LogBus = logBus
    fun resolver(): AppResolver = resolver
    fun firewall(): FirewallManager = (application as NetAverApp).firewall()
    fun geoIp(): GeoIp = (application as NetAverApp).geoIp()
    fun isRunning(): Boolean = running
    fun startTime(): Long = startTime

    /** True when this destination should pass through untouched (router web, printer, NAS...). */
    fun isLanBypass(dstIp: Int): Boolean {
        return dstIp != OUR_DNS_IP && hasPrefs() && prefs.bypassLan() && isLan(dstIp)
    }

    /** Mirrors Java's `prefs != null` guard (prefs is set in onCreate). */
    private fun hasPrefs(): Boolean = runCatching { prefs }.isSuccess

    // ---------------- DNS ----------------

    /** Bootstrap cache for custom hostnames (avoid repeated lookups). */
    private val bootstrapCache = HashMap<String, String>()

    /**
     * Resolve a hostname to IP via plain DNS to 1.1.1.1 on a protected
     * socket (bypasses our own VPN, no chicken-and-egg).
     */
    private fun bootstrapResolve(host: String): String? {
        synchronized(bootstrapCache) {
            val cached = bootstrapCache[host]
            if (cached != null) return cached
        }
        var ip: String? = null
        var ds: DatagramSocket? = null
        try {
            ds = DatagramSocket()
            protect(ds)
            ds.soTimeout = 4000
            val q = DnsMessage.buildQuery(host, 1) ?: return null
            val server = InetAddress.getByName("1.1.1.1")
            ds.send(DatagramPacket(q, q.size, server, 53))
            val buf = ByteArray(512)
            val rp = DatagramPacket(buf, buf.size)
            ds.receive(rp)
            val ips = DnsMessage.extractIps(buf, rp.length)
            if (ips.isNotEmpty()) ip = ips[0]
        } catch (e: Exception) {
            Log.d(TAG, "bootstrap resolve failed for $host", e)
        } finally {
            ds?.close()
        }
        if (ip != null) {
            synchronized(bootstrapCache) {
                if (bootstrapCache.size > 64) bootstrapCache.clear()
                bootstrapCache[host] = ip
            }
        }
        return ip
    }

    /** Build the effective upstream target from prefs (presets + custom). */
    /** Resolve the full ordered upstream list from prefs (AdGuard Home style). */
    private fun resolveUpstreamList(): List<UpstreamTarget> {
        val specs = prefs.upstreamList()
        if (specs.isEmpty()) {
            // safety net (migration should have filled this): Cloudflare preset
            val t = UpstreamTarget()
            t.proto = prefs.getProtocol()
            t.ip = Prefs.upstreamIp(0)
            t.tlsHost = Prefs.upstreamTlsHost(0)
            t.port = if (t.proto == 2) 443 else 853
            t.label = Prefs.protoName(t.proto) + " " + t.ip
            return listOf(t)
        }
        return specs.mapNotNull { spec -> specToTarget(spec) }.ifEmpty {
            // all specs invalid: fall back to Cloudflare rather than failing closed
            val t = UpstreamTarget()
            t.proto = prefs.getProtocol()
            t.ip = "1.1.1.1"
            t.tlsHost = "one.one.one.one"
            t.port = if (t.proto == 2) 443 else 853
            t.label = Prefs.protoName(t.proto) + " 1.1.1.1"
            listOf(t)
        }
    }

    /** "preset:0|1|2" or free-form spec -> resolved target (bootstrap if hostname). */
    private fun specToTarget(spec: String): UpstreamTarget? {
        val t = UpstreamTarget()
        if (spec.startsWith("preset:")) {
            val which = spec.removePrefix("preset:").toIntOrNull()?.coerceIn(0, 2) ?: return null
            t.proto = prefs.getProtocol()
            t.ip = Prefs.upstreamIp(which)
            t.tlsHost = Prefs.upstreamTlsHost(which)
            t.port = if (t.proto == 2) 443 else if (t.proto == 1) 853 else 53
            t.label = Prefs.protoName(t.proto) + " " + t.ip
            return t
        }
        fillCustomTarget(t, spec)
        return if (t.ip.isEmpty()) null else t
    }

    /** Resolve a free-form upstream spec (tls://, https://, IP, hostname). */
    private fun fillCustomTarget(t: UpstreamTarget, raw: String) {
        val s = Prefs.parseCustomUpstream(raw)
        if (!s.valid) {
            // fall back to Cloudflare rather than failing closed
            t.proto = prefs.getProtocol()
            t.ip = "1.1.1.1"
            t.tlsHost = "one.one.one.one"
            t.port = if (t.proto == 2) 443 else if (t.proto == 1) 853 else 53
            t.label = "custom invalid → 1.1.1.1"
            return
        }
        t.proto = if (s.protoOverride >= 0) s.protoOverride else prefs.getProtocol()
        if (Prefs.isValidIpv4(s.host)) {
            t.ip = s.host
            t.tlsHost = s.host
        } else {
            val rip = bootstrapResolve(s.host)
            if (rip == null) {
                t.proto = prefs.getProtocol()
                t.ip = "1.1.1.1"
                t.tlsHost = "one.one.one.one"
                t.port = if (t.proto == 2) 443 else if (t.proto == 1) 853 else 53
                t.label = "custom unresolvable → 1.1.1.1"
                return
            }
            t.ip = rip
            t.tlsHost = s.host // SNI = original hostname
        }
        t.dohPath = s.path
        val port = if (s.port > 0) s.port else if (t.proto == 2) 443 else if (t.proto == 1) 853 else 53
        t.port = port
        t.label = Prefs.protoName(t.proto) + " " + s.host
    }

    /** Create upstream transport for the resolved target. */
    private fun createUpstream(t: UpstreamTarget): DnsUpstream {
        return when (t.proto) {
            1 -> DotUpstream(this, t.ip, t.tlsHost)
            2 -> DohUpstream(this, t.ip, t.tlsHost, t.port, t.dohPath)
            else -> PlainUpstream(this, t.ip)
        }
    }

    /** Fingerprint of one resolved target (for conn pool + health maps). */
    private fun targetFp(t: UpstreamTarget): String =
        "${t.proto}|${t.ip}|${t.tlsHost}|${t.dohPath}|${t.port}"

    /** Fingerprint of the whole upstream config: re-resolve + drop conns when it changes. */
    private fun upstreamConfigFp(): String {
        val p = application as NetAverApp
        return "m${p.prefs().upstreamMode()}|${p.prefs().upstreamList().joinToString(",")}" +
            "|p${p.prefs().getProtocol()}|net${netEpoch.get()}"
    }

    /** Drop and close one pooled connection. */
    private fun dropConn(fp: String) {
        try { connMap.remove(fp)?.close() } catch (ignored: Exception) { }
    }

    private fun closeAllConns() {
        // close each pooled connection; dropConn removes it from the map.
        // (Never clear() first — remove(k) would then return null and the
        // socket would leak until server-side idle timeout.)
        val keys = connMap.keys.toList()
        for (k in keys) dropConn(k)
    }

    /**
     * Upstream config changed (mode/specs/network epoch): drop pooled
     * connections and reset health so in-flight queries killed by the
     * forced close aren't counted as failures against healthy upstreams.
     */
    private fun onUpstreamConfigChanged(fp: String) {
        cfgFp = fp
        closeAllConns()
        upstreamFails.clear()
        upstreamDown.clear()
    }

    /** Persistent connection for a target (one at a time per target; no handshake per query). */
    private fun connFor(t: UpstreamTarget, fp: String): DnsUpstream {
        connMap[fp]?.let { return it }
        val lock = connLocks.computeIfAbsent(fp) { Any() }
        synchronized(lock) {
            connMap[fp]?.let { return it }
            val up = createUpstream(t)
            connMap[fp] = up
            return up
        }
    }

    /** Single query against one target on its persistent connection. Null on failure. */
    private fun querySingle(t: UpstreamTarget, q: ByteArray): UpstreamAnswer? {
        val fp = targetFp(t)
        val lock = connLocks.computeIfAbsent(fp) { Any() }
        synchronized(lock) {
            try {
                val up = try { connFor(t, fp) } catch (e: Exception) { return null }
                val t0 = android.os.SystemClock.elapsedRealtime()
                val resp = try { up.query(q, q.size) } catch (e: Exception) { null }
                if (resp == null || resp.size < 12) {
                    dropConn(fp) // stale/broken socket: reconnect next time
                    return null
                }
                val ms = android.os.SystemClock.elapsedRealtime() - t0
                return UpstreamAnswer(resp, fp, t.label, ms)
            } catch (e: Exception) {
                dropConn(fp)
                return null
            }
        }
    }

    /** Result of a multi-upstream query: winner data. */
    private class UpstreamAnswer(
        val resp: ByteArray,
        val winnerFp: String,
        val winnerLabel: String,
        val latencyMs: Long
    )

    /** Full outcome: winner (null = all failed) + fps that actually failed. */
    private class UpstreamQueryResult(
        val answer: UpstreamAnswer?,
        val failedFps: List<String>
    )

    /**
     * Query upstreams per the configured mode. Battery-conscious:
     * persistent connections (no per-query TLS handshakes), blocking I/O only.
     * Modes: 0=parallel (race all, fastest wins), 1=fastest (lowest latency EMA
     * first, unknown upstreams get one learning query first), 2=sequential.
     */
    private fun queryUpstreams(
        targets: List<UpstreamTarget>, mode: Int, qdata: ByteArray, qlen: Int
    ): UpstreamQueryResult {
        if (targets.isEmpty()) return UpstreamQueryResult(null, emptyList())
        val healthy = targets.filter { upstreamDown[targetFp(it)] != true }
        val cands = if (healthy.isNotEmpty()) healthy else targets // all down: best effort
        if (cands.size == 1) {
            val fp = targetFp(cands[0])
            val a = querySingle(cands[0], qdata.copyOf(qlen))
            return if (a != null) UpstreamQueryResult(a, emptyList())
            else UpstreamQueryResult(null, listOf(fp))
        }
        return when (mode) {
            Prefs.MODE_FASTEST -> queryOrdered(orderByEma(cands), qdata, qlen)
            Prefs.MODE_SEQUENTIAL -> queryOrdered(cands, qdata, qlen)
            else -> queryParallel(cands, qdata, qlen)
        }
    }

    /** Order by latency EMA (unknown first: one learning query, then it sorts itself). */
    private fun orderByEma(cands: List<UpstreamTarget>): List<UpstreamTarget> {
        return cands.sortedWith { a, b ->
            val ea = upstreamEma[targetFp(a)]
            val eb = upstreamEma[targetFp(b)]
            when {
                ea == null && eb == null -> 0
                ea == null -> -1
                eb == null -> 1
                else -> ea.compareTo(eb)
            }
        }
    }

    private fun queryOrdered(
        cands: List<UpstreamTarget>, qdata: ByteArray, qlen: Int
    ): UpstreamQueryResult {
        val failed = ArrayList<String>()
        for (t in cands) {
            val fp = targetFp(t)
            val a = querySingle(t, qdata.copyOf(qlen))
            if (a != null) return UpstreamQueryResult(a, failed)
            failed.add(fp)
        }
        return UpstreamQueryResult(null, failed)
    }

    /**
     * Race all candidates; fastest valid response wins. Uses a small fixed pool
     * of I/O-blocked threads (no extra CPU when idle). Only upstreams that
     * actually FAILED get a failure tick — slow losers are not punished.
     */
    private fun queryParallel(
        cands: List<UpstreamTarget>, qdata: ByteArray, qlen: Int
    ): UpstreamQueryResult {
        val exec = raceExec
        // executor gone or shutting down (race with stopVpn): fall back to ordered
        if (exec == null || exec.isShutdown) return queryOrdered(cands, qdata, qlen)
        val q = qdata.copyOf(qlen)
        val win = AtomicReference<UpstreamAnswer?>()
        val latch = CountDownLatch(1)
        val failed = ConcurrentHashMap<String, Boolean>()
        val futures = ArrayList<java.util.concurrent.Future<*>>(cands.size)
        for (t in cands) {
            val fp = targetFp(t)
            val f = try {
                exec.submit {
                    try {
                        val a = querySingle(t, q)
                        if (a != null) {
                            if (win.compareAndSet(null, a)) latch.countDown()
                        } else {
                            failed[fp] = true
                        }
                    } catch (ignored: Exception) {
                        failed[fp] = true
                    }
                }
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                // shutting down mid-race: treat as failed, keep other candidates
                failed[fp] = true
                null
            }
            if (f != null) futures.add(f)
        }
        try {
            latch.await(RACE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        // losers still in flight are NOT marked failed (outcome unknown);
        // cancel only unblocks pool bookkeeping, sockets end on their own timeout
        for (f in futures) f.cancel(true)
        return UpstreamQueryResult(win.get(), failed.keys.toList())
    }

    // ---------------- upstream health (per-target failover) ----------------

    /** Success: reset streak, feed latency EMA (drives "fastest" mode + UI). */
    private fun noteUpstreamSuccess(fp: String, latencyMs: Long) {
        upstreamFails[fp]?.set(0)
        val prev = upstreamEma[fp]
        upstreamEma[fp] = if (prev == null) latencyMs else (prev * 3 + latencyMs) / 4
        updateUpstreamStatus()
    }

    /**
     * Failure: after [FAILOVER_THRESHOLD] consecutive failures the target is
     * marked down and skipped until the probe thread revives it.
     */
    private fun noteUpstreamFailure(fp: String) {
        val n = upstreamFails.computeIfAbsent(fp) { AtomicInteger(0) }.incrementAndGet()
        if (n >= FAILOVER_THRESHOLD && upstreamDown.putIfAbsent(fp, true) == null) {
            Log.i(TAG, "upstream down: $fp")
            debugEvent("upstream_down", fp)
            updateUpstreamStatus()
        }
    }

    private fun updateUpstreamStatus() {
        val p = try { (application as NetAverApp).prefs() } catch (e: Exception) { null }
        val mode = p?.upstreamModeName() ?: "Paralel"
        val n = p?.upstreamList()?.size ?: 0
        val down = upstreamDown.size
        upstreamStatusLine = if (down > 0) "$mode · $n upstream · $down DOWN"
        else "$mode · $n upstream"
    }

    /** Probe DOWN upstreams only (never scans healthy ones — battery rule). Runs on probeThread. */
    private fun probeDownUpstreams() {
        val p = application as NetAverApp
        val targets = resolveUpstreamList()
        for (t in targets) {
            if (!running) return
            val fp = targetFp(t)
            if (upstreamDown[fp] != true) continue
            var probe: DnsUpstream? = null
            try {
                probe = createUpstream(t)
                val resp = probe.query(PROBE_QUERY, PROBE_QUERY.size)
                if (resp != null && resp.size >= 12) {
                    upstreamDown.remove(fp)
                    upstreamFails[fp]?.set(0)
                    Log.i(TAG, "upstream recovered: $fp")
                    debugEvent("probe_ok", "upstream recovered: ${t.label}")
                    updateUpstreamStatus()
                }
            } catch (e: Exception) {
                Log.d(TAG, "upstream still down: ${t.label}")
            } finally {
                try { probe?.close() } catch (ignored: Exception) { }
            }
        }
    }

    /**
     * Daily blocklist check while the VPN stays on: the start trigger alone
     * never fires for an always-on VPN. Runs the same conditional refresh
     * once 24h have passed since the last check of any kind (the watermark
     * lives in Prefs and is stamped by refreshCustomLists itself).
     */
    private fun maybeDailyListCheck() {
        try {
            val last = prefs.lastListCheck()
            if (last == 0L) return // no check yet: the start path handles it
            if (System.currentTimeMillis() - last < DAILY_LIST_CHECK_MS) return
            if (networkLost) return // offline: retry on a later tick
            Thread({
                try {
                    blocklists.refreshCustomLists()
                } catch (e: Exception) {
                    Log.w(TAG, "daily list check failed", e)
                }
            }, "bl-daily").start()
        } catch (ignored: Exception) {
        }
    }

    /** Started in onCreate: every 60s revive down upstreams (only). */
    private fun startProbeThread() {
        probeThread = Thread({
            while (running) {
                try {
                    Thread.sleep(PROBE_INTERVAL_MS)
                } catch (e: InterruptedException) {
                    break
                }
                if (running && upstreamDown.isNotEmpty()) probeDownUpstreams()
                if (running) maybeDailyListCheck()
            }
        }, "upstream-probe")
        probeThread!!.isDaemon = true
        probeThread!!.start()
    }

    private fun dnsLoop() {
        try {
            while (running) {
                val query = try {
                    dnsQueue.take()
                } catch (e: InterruptedException) {
                    break
                }
                try {
                    // re-resolve config when prefs/mode/network changed; drop stale conns
                    val fp = upstreamConfigFp()
                    if (fp != cfgFp) onUpstreamConfigChanged(fp)
                    handleDns(query)
                } catch (e: Exception) {
                    // never let one bad query kill the worker permanently
                    if (running) android.util.Log.w("NetAverDNS", "dns worker", e)
                }
            }
        } finally {
            // pooled connections are closed on stopVpn / config change
        }
    }

    /** Dedicated worker for DNS-over-TCP queries. */
    private fun tcpDnsLoop() {
        try {
            while (running) {
                val task = try {
                    tcpDnsQueue.take()
                } catch (e: InterruptedException) {
                    break
                }
                try {
                    if (networkLost) {
                        // offline: serve cache/blocklist only, fail fast otherwise; nothing logged.
                        // (checked first so no upstream is created and no failover is triggered)
                        val ro = processDnsQueryOffline(task.query, task.query.size)
                        val offlineResp = ro?.resp
                        if (offlineResp != null) tcpDns?.respond(task.session, offlineResp)
                        continue
                    }
                    val fp = upstreamConfigFp()
                    if (fp != cfgFp) onUpstreamConfigChanged(fp)
                    val r = processDnsQuery(task.query, task.query.size,
                        task.uid, task.app) ?: continue
                    val resp = r.resp ?: continue
                    r.bypass = !task.bypassServer.isNullOrEmpty()
                    tcpDns?.respond(task.session, resp)
                    afterDns(r, task.uid, task.app)
                } catch (e: Exception) {
                    // never let one bad query kill the worker permanently
                    if (running) android.util.Log.w("NetAverDNS", "tcpdns worker", e)
                }
            }
        } finally {
        }
    }

    private fun processDnsQuery(
        qdata: ByteArray, qlen: Int, uid: Int, app: String
    ): DnsResult? {
        val msg = DnsMessage.parseQuery(qdata, qlen)
        if (!msg.ok) return null
        val t0 = System.currentTimeMillis()

        val r = DnsResult()
        r.qname = msg.qname ?: ""
        r.qtype = msg.qtype
        val resp: ByteArray?
        var blocked = false
        val matchInfo: String
        // user custom rules (AdGuard Home style): allowlist (@@) wins over everything
        val custom = (application as NetAverApp).customRules().match(msg.qname)
        if (custom > 0) {
            blocked = true
            resp = DnsMessage.buildBlockedResponse(msg)
            matchInfo = "Custom rule"
        } else if (custom < 0) {
            // allowlisted: serve from cache when possible, else upstream
            val cached = cacheLookup(msg)
            if (cached != null) {
                matchInfo = "Cache"
                resp = cached
            } else {
                matchInfo = "Allowlist rule"
                r.upstreamHit = true
                resp = queryUpstreamMulti(qdata, qlen)?.resp
                cacheStore(msg, resp)
            }
        } else {
            val src = blocklists.blocklist().matchSource(msg.qname)
            if (src != null) {
                blocked = true
                resp = DnsMessage.buildBlockedResponse(msg)
                matchInfo = blocklists.displayNameForSource(src)
            } else {
                val cached = cacheLookup(msg)
                if (cached != null) {
                    matchInfo = "Cache"
                    resp = cached
                } else {
                    r.upstreamHit = true
                    val ans = queryUpstreamMulti(qdata, qlen)
                    if (ans != null) {
                        resp = ans.resp
                        matchInfo = "Upstream " + ans.winnerLabel
                    } else {
                        // all upstreams failed: fail fast with SERVFAIL instead of
                        // dropping silently (client would hang for its full timeout)
                        resp = DnsMessage.buildServFail(msg)
                        matchInfo = "Upstream (all failed)"
                    }
                    // never cache SERVFAIL
                    if (resp != null && matchInfo != "Upstream (all failed)") cacheStore(msg, resp)
                }
            }
        }
        r.blocked = blocked
        r.resp = resp
        r.latencyMs = System.currentTimeMillis() - t0
        r.matchInfo = matchInfo
        if (resp != null && !blocked) {
            val ips = DnsMessage.extractIps(resp, resp.size)
            if (ips.isNotEmpty()) r.resolvedIp = ips[0]
        }
        return r
    }

    /**
     * Multi-upstream query with per-target health accounting.
     * Returns the winning answer (null when every candidate failed).
     */
    private fun queryUpstreamMulti(qdata: ByteArray, qlen: Int): UpstreamAnswer? {
        val p = application as NetAverApp
        val targets = resolveUpstreamList()
        val mode = p.prefs().upstreamMode()
        val qr = queryUpstreams(targets, mode, qdata, qlen)
        for (fp in qr.failedFps) noteUpstreamFailure(fp)
        val ans = qr.answer
        if (ans != null) {
            noteUpstreamSuccess(ans.winnerFp, ans.latencyMs)
            updateLatencyEma(ans.latencyMs) // passive UI latency (zero extra traffic)
        }
        return ans
    }

    // ---------------- upstream failover ----------------

    /** Cache lookup (query ID rewritten on hit). Null when disabled/miss. */
    private fun cacheLookup(msg: DnsMessage): ByteArray? {
        if (!prefs.dnsCacheEnabled()) return null
        return (application as NetAverApp).dnsCache().get(msg.qname ?: "", msg.qtype, msg.id)
    }

    /**
     * Offline DNS: local filtering still applies (custom rules, blocklist),
     * cache is served, everything else fails fast with SERVFAIL.
     * Nothing is logged while offline.
     */
    private fun processDnsQueryOffline(qdata: ByteArray, qlen: Int): DnsResult? {
        val msg = DnsMessage.parseQuery(qdata, qlen)
        if (!msg.ok) return null
        val r = DnsResult()
        r.qname = msg.qname ?: ""
        r.qtype = msg.qtype
        val resp: ByteArray?
        val custom = (application as NetAverApp).customRules().match(msg.qname)
        if (custom < 0) {
            // allowlist wins (mirrors online): serve cache, else fail fast
            val cached = cacheLookup(msg)
            resp = cached ?: DnsMessage.buildServFail(msg)
            r.matchInfo = if (cached != null) "Cache (offline)" else "Offline"
        } else if (custom > 0) {
            r.blocked = true
            resp = DnsMessage.buildBlockedResponse(msg)
            r.matchInfo = "Custom rule"
        } else {
            val src = blocklists.blocklist().matchSource(msg.qname)
            if (src != null) {
                r.blocked = true
                resp = DnsMessage.buildBlockedResponse(msg)
                r.matchInfo = blocklists.displayNameForSource(src)
            } else {
                val cached = cacheLookup(msg)
                if (cached != null) {
                    resp = cached
                    r.matchInfo = "Cache (offline)"
                } else {
                    resp = DnsMessage.buildServFail(msg)
                    r.matchInfo = "Offline"
                }
            }
        }
        r.resp = resp
        r.latencyMs = 0
        if (resp != null && !r.blocked) {
            val ips = DnsMessage.extractIps(resp, resp.size)
            if (ips.isNotEmpty()) r.resolvedIp = ips[0]
        }
        return r
    }

    /** Store an upstream response in cache (honors TTL). */
    private fun cacheStore(msg: DnsMessage, resp: ByteArray?) {
        if (resp == null || !prefs.dnsCacheEnabled()) return
        (application as NetAverApp).dnsCache().put(msg.qname ?: "", msg.qtype, resp, resp.size)
    }

    /** Log the entry + geo lookup + notification refresh (shared UDP/TCP). */
    private fun afterDns(r: DnsResult, uid: Int, app: String) {
        val entry = Entries.DnsEntry(
            System.currentTimeMillis(), r.qname,
            DnsMessage.qtypeName(r.qtype), app, uid, r.blocked, r.latencyMs, r.resolvedIp
        )
        entry.matchInfo = r.matchInfo
        entry.isBypass = r.bypass
        if (r.resolvedIp.isNotEmpty()) {
            entry.countryCode = geoIp().cached(r.resolvedIp)
            geoIp().resolve(r.resolvedIp)
        }
        logBus.addDns(entry)
        if (r.blocked) scheduleNotifUpdate()
    }

    private fun handleDns(query: ByteArray) {
        val p = IpPacket.parse(query, query.size) ?: return
        if (p.protocol != IpPacket.PROTO_UDP) return
        val qoff = p.udpPayloadOffset()
        val qlen = p.udpPayloadLen()
        if (qlen <= 0) return
        val qdata = ByteArray(qlen)
        System.arraycopy(query, qoff, qdata, 0, qlen)

        val uid = resolver.uidFor(AppResolver.protoUdp(), p.srcIp, p.udpSrcPort(), p.dstIp, 53)
        val app = resolver.labelForUid(uid)

        if (networkLost) {
            // offline: serve cache/blocklist only, fail fast otherwise; nothing logged
            val r = processDnsQueryOffline(qdata, qlen)
            val offlineResp = r?.resp
            if (offlineResp != null) {
                val out = ByteArray(28 + offlineResp.size)
                val total = IpPacket.buildUdp(
                    out, p.dstIp, p.srcIp, 53, p.udpSrcPort(),
                    offlineResp, 0, offlineResp.size
                )
                writeTun(out, total)
            }
            return
        }

        val r = processDnsQuery(qdata, qlen, uid, app) ?: return
        // health accounting already done inside queryUpstreamMulti (per-target);
        // cache/blocked hits are neutral
        r.bypass = isBypassDns(p.dstIp) // hardcoded DNS (e.g. 8.8.8.8), not 10.8.0.1
        val resp = r.resp
        if (resp != null) {
            val out = ByteArray(28 + resp.size)
            val total = IpPacket.buildUdp(
                out, p.dstIp, p.srcIp, 53, p.udpSrcPort(),
                resp, 0, resp.size
            )
            writeTun(out, total)
        }
        afterDns(r, uid, app)
    }

    /** Enqueue a DNS-over-TCP query from TcpDns (called on TUN thread). */
    fun enqueueTcpDns(task: TcpDns.Task) {
        if (!tcpDnsQueue.offer(task)) Log.d(TAG, "tcp dns queue full, dropping")
    }

    /**
     * Log a blocked DNS-bypass attempt (DoT on port 853) into the DNS log
     * so the user can see which app tried to dodge the filter.
     * Throttled to one entry per (app, server) per 60s to avoid spam.
     */
    private fun logBypassAttempt(p: IpPacket, tcp: Boolean) {
        val uid = if (tcp) {
            resolver.uidFor(AppResolver.protoTcp(), p.srcIp, p.tcpSrcPort(), p.dstIp, 853)
        } else {
            resolver.uidFor(AppResolver.protoUdp(), p.srcIp, p.udpSrcPort(), p.dstIp, 853)
        }
        val app = resolver.labelForUid(uid)
        val server = IpPacket.ipToString(p.dstIp)
        val key = "$app|$server"
        val now = System.currentTimeMillis()
        synchronized(bypassThrottle) {
            val last = bypassThrottle[key]
            if (last != null && now - last < 60_000) return
            if (bypassThrottle.size > 200) bypassThrottle.clear()
            bypassThrottle[key] = now
        }
        val e = Entries.DnsEntry(now, server, "DoT", app, uid, true, 0, "")
        e.matchInfo = "Bypass blocked (port 853)"
        e.isBypass = true
        logBus.addDns(e)
        scheduleNotifUpdate()
    }

    /** Current upstream label for UI. */
    fun currentUpstreamLabel(): String {
        return prefs.upstreamLabel()
    }

    // ---------------- notification ----------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val ch = NotificationChannel(CHANNEL_ID, "NetAver DNS", NotificationManager.IMPORTANCE_LOW)
        ch.description = "VPN protection status"
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(): Notification {
        val i = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, i,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val totals = logBus.totalsAll()
        var title = getString(R.string.vpn_notification_title)
        val text: String
        if (networkLost) {
            title += " · offline"
            text = "Tidak ada koneksi internet — menunggu…"
        } else {
            text = getString(R.string.vpn_notification_text, totals[1])
        }
        val nb = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
        // Quick toggle: stop the VPN right from the notification shade
        val stopIntent = Intent(this, VpnToggleReceiver::class.java).setAction(ACTION_STOP_VPN)
        val stopPi = PendingIntent.getBroadcast(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        nb.addAction(Notification.Action.Builder(
            android.R.drawable.ic_menu_close_clear_cancel, "Matikan", stopPi).build())
        if (Build.VERSION.SDK_INT >= 26) nb.setChannelId(CHANNEL_ID)
        return nb.build()
    }

    /** Refresh the foreground notification immediately (e.g. offline state changed). */
    fun updateNotificationNow() {
        if (!running) return
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.notify(NOTIF_ID, buildNotification())
        } catch (e: Exception) {
            Log.d(TAG, "notif update failed", e)
        }
    }

    private fun scheduleNotifUpdate() {
        if (!prefs.showNotif() || !notifUpdatePending.compareAndSet(false, true)) return
        mainHandler.postDelayed({
            notifUpdatePending.set(false)
            if (running && prefs.showNotif()) {
                val nm = getSystemService(NotificationManager::class.java)
                nm?.notify(NOTIF_ID, buildNotification())
                // re-arm throttled refresh every 60s while running
                mainHandler.postDelayed(this::scheduleNotifUpdate, 60_000L)
            }
        }, 5000)
    }
}
