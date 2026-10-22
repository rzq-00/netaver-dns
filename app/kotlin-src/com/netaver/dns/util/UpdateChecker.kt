package com.netaver.dns.util

import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * In-app update check against the PUBLIC GitHub repo's Releases
 * (rzq-00/netaver-dns). Read-only and unauthenticated — no token ever
 * ships in the app. Responses are capped; failures are silent (null).
 */
object UpdateChecker {
    private const val API =
        "https://api.github.com/repos/rzq-00/netaver-dns/releases?per_page=10"
    private const val MAX_BYTES = 512 * 1024

    class ReleaseInfo(
        val tag: String,          // "v2.3.2"
        val version: String,      // "2.3.2"
        val notes: String,        // raw release body (markdown-ish)
        val publishedAt: String,  // ISO from GitHub
        val apkUrl: String,
        val apkSize: Long
    )

    /** Parse a GitHub releases JSON array into ReleaseInfo items (newest first). */
    fun parse(json: String): List<ReleaseInfo> {
        val out = ArrayList<ReleaseInfo>()
        try {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) {
                val r = arr.getJSONObject(i)
                if (r.optBoolean("draft") || r.optBoolean("prerelease")) continue
                val tag = r.optString("tag_name")
                if (tag.isEmpty()) continue
                var url = ""
                var size = 0L
                val assets = r.optJSONArray("assets")
                if (assets != null) {
                    for (j in 0 until assets.length()) {
                        val a = assets.getJSONObject(j)
                        if (a.optString("name").endsWith(".apk")) {
                            url = a.optString("browser_download_url")
                            size = a.optLong("size")
                            break
                        }
                    }
                }
                if (url.isEmpty()) continue
                out.add(ReleaseInfo(tag, tag.removePrefix("v"),
                    r.optString("body"), r.optString("published_at"), url, size))
            }
        } catch (e: Exception) {
            // malformed cache/response -> no releases
        }
        return out
    }

    /** Fetch the releases list on a background thread; cb on the main thread. */
    fun fetch(cb: (List<ReleaseInfo>?, String?) -> Unit) {
        Thread({
            var raw: String? = null
            try {
                val c = URL(API).openConnection() as HttpURLConnection
                c.connectTimeout = 10000
                c.readTimeout = 15000
                c.setRequestProperty("Accept", "application/vnd.github+json")
                c.setRequestProperty("User-Agent", "NetAver-DNS")
                if (c.responseCode == 200) {
                    val buf = ByteArrayOutputStream()
                    val tmp = ByteArray(8192)
                    c.inputStream.use { ins ->
                        var n: Int
                        while (ins.read(tmp).also { n = it } > 0) {
                            buf.write(tmp, 0, n)
                            if (buf.size() > MAX_BYTES) break
                        }
                    }
                    raw = buf.toString("UTF-8")
                }
                c.disconnect()
            } catch (e: Exception) {
                raw = null
            }
            val r = raw
            val list = if (r != null) parse(r) else null
            Handler(Looper.getMainLooper()).post { cb(list, r) }
        }, "update-check").start()
    }

    /** true when [a] (e.g. "2.3.2") is a strictly newer version than [b]. */
    fun isNewer(a: String, b: String): Boolean {
        val pa = parts(a)
        val pb = parts(b)
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    private fun parts(v: String): List<Int> =
        v.removePrefix("v").split('.').map { it.toIntOrNull() ?: 0 }

    /** "2026-10-22T01:00:00Z" -> "22 Oct 2026" in the device's locale. */
    fun displayDate(iso: String): String {
        return try {
            val p = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            p.timeZone = TimeZone.getTimeZone("UTC")
            val d = p.parse(iso) ?: return iso
            SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(d)
        } catch (e: Exception) {
            iso
        }
    }

    /** Strip the markdown we use in release notes down to readable plain text. */
    fun plainNotes(md: String): String {
        val sb = StringBuilder()
        for (raw in md.replace("\r\n", "\n").split("\n")) {
            var line = raw.trim()
            line = line.removePrefix("## ").removePrefix("# ")
            if (line.startsWith("- ") || line.startsWith("* ")) {
                line = "• " + line.substring(2)
            }
            line = line.replace("**", "")
            sb.append(line).append('\n')
        }
        return sb.toString().trim()
    }

    fun fmtSize(bytes: Long): String {
        if (bytes <= 0) return "?"
        val mb = bytes / (1024.0 * 1024.0)
        return if (mb >= 0.1) String.format(Locale.US, "%.1f MB", mb)
        else String.format(Locale.US, "%d KB", bytes / 1024)
    }
}
