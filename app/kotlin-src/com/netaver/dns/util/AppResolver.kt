package com.netaver.dns.util

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.system.OsConstants
import android.util.Log

import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves which app owns a flow, via ConnectivityManager.getConnectionOwnerUid.
 * Heavily cached: kernel lookup happens at most once per flow — battery friendly.
 */
class AppResolver(ctx: Context) {
    private val cm: ConnectivityManager? =
        ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val pm: PackageManager = ctx.packageManager
    /** 5-tuple -> (uid, cachedAt). Entries expire (port reuse across apps)
     *  and are explicitly invalidated when a proxied session closes. */
    private val flowToUid = ConcurrentHashMap<String, Pair<Int, Long>>()
    private val uidToLabel = ConcurrentHashMap<Int, String>()

    companion object {
        private const val TAG = "AppResolver"
        private const val FLOW_CACHE_CAP = 4096
        /** Flow->UID entries expire after this; ephemeral ports get reused. */
        private const val FLOW_CACHE_TTL_MS = 60_000L

        @JvmStatic
        fun protoTcp(): Int = OsConstants.IPPROTO_TCP

        @JvmStatic
        fun protoUdp(): Int = OsConstants.IPPROTO_UDP

        private fun addrOf(ip: Int): InetAddress {
            val b = ByteBuffer.allocate(4).putInt(ip).array()
            return InetAddress.getByAddress(b)
        }
    }

    /** Combined helper: "App label" for a TUN packet flow. Never blocks UI. */
    fun appFor(proto: Int, srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int): String {
        val uid = uidFor(proto, srcIp, srcPort, dstIp, dstPort)
        return labelForUid(uid)
    }

    fun uidFor(proto: Int, srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int): Int {
        val key = "$proto:$srcIp:$srcPort:$dstIp:$dstPort"
        val now = System.currentTimeMillis()
        flowToUid[key]?.let { (uid, at) ->
            // stale after TTL: the ephemeral port may have been reused by
            // another app after the original flow closed
            if (now - at < FLOW_CACHE_TTL_MS) return uid
            flowToUid.remove(key)
        }
        var uid = -1
        try {
            if (Build.VERSION.SDK_INT >= 29 && cm != null) {
                val local = InetSocketAddress(addrOf(srcIp), srcPort)
                val remote = InetSocketAddress(addrOf(dstIp), dstPort)
                uid = cm.getConnectionOwnerUid(proto, local, remote)
            }
        } catch (e: Exception) {
            Log.d(TAG, "uid lookup failed", e)
        }
        if (flowToUid.size > FLOW_CACHE_CAP) flowToUid.clear()
        flowToUid[key] = uid to now
        return uid
    }

    /** Drop a cached flow (call when a proxied TCP/UDP session closes). */
    fun invalidateFlow(proto: Int, srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int) {
        flowToUid.remove("$proto:$srcIp:$srcPort:$dstIp:$dstPort")
    }

    fun labelForUid(uid: Int): String {
        if (uid < 0) return "System"
        uidToLabel[uid]?.let { return it }
        var label = "UID $uid"
        try {
            val pkgs = pm.getPackagesForUid(uid)
            if (pkgs != null && pkgs.isNotEmpty()) {
                val ai = pm.getApplicationInfo(pkgs[0], 0)
                val l = pm.getApplicationLabel(ai)
                if (l != null) label = l.toString()
            }
        } catch (_: Exception) {
        }
        if (uidToLabel.size > 1024) uidToLabel.clear()
        uidToLabel[uid] = label
        return label
    }

    /** Drop caches (e.g. on VPN restart). */
    fun clear() {
        flowToUid.clear()
        uidToLabel.clear()
    }
}
