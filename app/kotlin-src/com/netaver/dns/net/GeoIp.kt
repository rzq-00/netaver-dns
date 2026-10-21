package com.netaver.dns.net

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.BlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue

/**
 * IP -> country resolver for the "country flag in logs" feature.
 * Battery-friendly: memory + disk cache, single worker thread, one HTTP
 * request per unknown public IP (free ip-api.com endpoint). Private IPs
 * are skipped (no flag).
 */
class GeoIp(ctx: Context) {

    fun interface Listener {
        fun onResolved(ip: String, countryCode: String)
    }

    private val diskFile = File(ctx.cacheDir, "geoip.txt")
    private val mem: MutableMap<String, String> = ConcurrentHashMap()
    private val queue: BlockingQueue<String> = LinkedBlockingQueue()
    private val listeners = CopyOnWriteArrayList<Listener>()
    @Volatile private var enabled = true
    private var diskCount = 0

    init {
        loadDisk()
        val t = Thread(Runnable { worker() }, "geoip")
        t.isDaemon = true
        t.start()
    }

    fun setEnabled(e: Boolean) { enabled = e }

    fun addListener(l: Listener) { listeners.addIfAbsent(l) }
    fun removeListener(l: Listener) { listeners.remove(l) }

    /** Cached country code, or "" if unknown. Never blocks. */
    fun cached(ip: String): String = mem[ip] ?: ""

    /** Enqueue async resolution if not cached. */
    fun resolve(ip: String?) {
        if (!enabled || ip == null || mem.containsKey(ip) || isPrivate(ip)) return
        queue.offer(ip)
    }

    private fun worker() {
        while (true) {
            val ip = try { queue.take() } catch (e: InterruptedException) { return }
            if (mem.containsKey(ip) || !enabled) continue
            val cc = lookup(ip)
            mem[ip] = cc // "" = failed/unknown, cached to avoid retry storms
            if (cc.isNotEmpty()) appendDisk(ip, cc)
            for (l in listeners) {
                try { l.onResolved(ip, cc) } catch (_: Exception) {}
            }
            // be gentle with the free tier: max ~40 req/min
            try { Thread.sleep(1500) } catch (e: InterruptedException) { return }
        }
    }

    private fun lookup(ip: String): String {
        var c: HttpURLConnection? = null
        try {
            val url = URL("https://ip-api.com/json/$ip?fields=status,countryCode")
            c = url.openConnection() as HttpURLConnection
            c.connectTimeout = 8000
            c.readTimeout = 8000
            c.setRequestProperty("User-Agent", "NetAverDNS/1.1")
            if (c.responseCode != 200) return ""
            val sb = StringBuilder()
            BufferedReader(InputStreamReader(c.inputStream)).use { r ->
                var line: String?
                while (r.readLine().also { line = it } != null) sb.append(line)
            }
            val json = sb.toString()
            if (!json.contains("\"success\"")) return ""
            val i = json.indexOf("\"countryCode\"")
            if (i < 0) return ""
            val q1 = json.indexOf('"', i + 14)
            val q2 = json.indexOf('"', q1 + 1)
            if (q1 < 0 || q2 < 0) return ""
            val cc = json.substring(q1 + 1, q2)
            return if (cc.length == 2) cc else ""
        } catch (e: Exception) {
            Log.d(TAG, "lookup failed for $ip", e)
            return ""
        } finally {
            c?.disconnect()
        }
    }

    private fun loadDisk() {
        if (!diskFile.exists()) return
        try {
            BufferedReader(FileReader(diskFile)).use { r ->
                var line: String?
                while (r.readLine().also { line = it } != null && diskCount < DISK_CAP) {
                    val l = line ?: break
                    val comma = l.indexOf(',')
                    if (comma < 0) continue
                    val ip = l.substring(0, comma).trim()
                    val cc = l.substring(comma + 1).trim()
                    if (ip.isNotEmpty() && cc.length == 2) {
                        mem[ip] = cc
                        diskCount++
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "geoip disk load", e)
        }
    }

    @Synchronized
    private fun appendDisk(ip: String, cc: String) {
        if (diskCount >= DISK_CAP) return
        try {
            FileWriter(diskFile, true).use { w ->
                w.write("$ip,$cc\n")
                diskCount++
            }
        } catch (e: Exception) {
            Log.d(TAG, "geoip disk append", e)
        }
    }

    companion object {
        private const val TAG = "GeoIp"
        private const val DISK_CAP = 5000

        /** Country code -> flag emoji (regional indicators). "" if unknown. */
        @JvmStatic
        fun flagFor(cc: String?): String {
            if (cc == null || cc.length != 2) return ""
            val a = Character.toUpperCase(cc[0])
            val b = Character.toUpperCase(cc[1])
            if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return ""
            return String(Character.toChars(a - 'A' + 0x1F1E6)) +
                    String(Character.toChars(b - 'A' + 0x1F1E6))
        }

        private fun isPrivate(ip: String): Boolean {
            if (ip.startsWith("10.") || ip.startsWith("192.168.")
                || ip.startsWith("127.") || ip.startsWith("0.")
                || ip.startsWith("169.254.")) return true
            // 172.16.0.0/12 — careful: "172.2" would also match public 172.2.x.x
            if (!ip.startsWith("172.")) return false
            val second = ip.substring(4).substringBefore('.').toIntOrNull() ?: return false
            return second in 16..31
        }
    }
}
