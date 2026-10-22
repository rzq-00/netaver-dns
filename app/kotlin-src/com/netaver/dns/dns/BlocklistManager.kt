package com.netaver.dns.dns

import android.content.Context
import android.util.Log

import com.netaver.dns.util.Prefs

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.DigestInputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Loads the built-in list + user custom URLs (e.g. Hagezi) into a Blocklist. */
class BlocklistManager(ctx: Context, private val prefs: Prefs) {

    class ListInfo(
        val name: String,
        /** "bundled" or URL */
        val source: String,
        val enabled: Boolean,
        val rules: Int,
        /** null if ok */
        val error: String?
    )

    class CustomList(
        var name: String,
        var url: String,
        var enabled: Boolean
    )

    private val ctx: Context = ctx.applicationContext
    private val blocklist = Blocklist()
    // per-source rule counts + errors for UI
    private val sourceCounts: MutableMap<String, Int> = HashMap()
    private val sourceErrors: MutableMap<String, String?> = HashMap()
    private val changeListeners: MutableList<Runnable> = ArrayList()

    fun addChangeListener(r: Runnable) {
        synchronized(changeListeners) { changeListeners.add(r) }
    }

    private fun notifyChanged() {
        synchronized(changeListeners) {
            for (r in changeListeners) {
                try { r.run() } catch (_: Exception) {}
            }
        }
    }

    fun blocklist(): Blocklist = blocklist

    /** Load bundled list (fast, on any thread). Custom URLs load in background. */
    fun loadBundled() {
        val set = HashSet<String>()
        var n = 0
        try {
            ctx.assets.open("blocklist.txt").use { ins ->
                BufferedReader(InputStreamReader(ins)).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        for (d in Blocklist.parseLine(line)) if (set.add(d)) n++
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "bundled list failed", e)
        }
        synchronized(sourceCounts) {
            sourceCounts["bundled"] = if (prefs.builtinEnabled()) n else 0
        }
        val src = LinkedHashMap<String, Set<String>>()
        if (prefs.builtinEnabled()) src["bundled"] = set
        // custom lists: serve from disk cache instantly (no re-download needed)
        for (cl in customLists()) {
            if (!cl.enabled) {
                synchronized(sourceCounts) { sourceCounts[cl.url] = 0 }
                continue
            }
            val cached = HashSet<String>()
            val cn = readCache(cl.url, cached)
            if (cn > 0) src[cl.url] = cached
            synchronized(sourceCounts) { sourceCounts[cl.url] = cn }
            synchronized(sourceErrors) { sourceErrors.remove(cl.url) }
        }
        blocklist.replaceSources(src)
        notifyChanged()
    }

    /** Auto-check on VPN start: any enabled cache missing, or no check in the last hour. */
    fun shouldAutoCheck(): Boolean {
        for (cl in customLists()) {
            if (!cl.enabled) continue
            if (!File(cacheDir(), cacheName(cl.url)).exists()) return true
        }
        return System.currentTimeMillis() - prefs.lastListCheck() > CHECK_MIN_MS
    }

    /** Outcome counters for one refresh round (for the visible status line). */
    private class Tally {
        var updated = 0
        var unchanged = 0
        var failed = 0
    }

    /** Conditional-check + merge custom URL lists. Runs on caller thread (call off-main). */
    fun refreshCustomLists() {
        prefs.setLastListCheck(System.currentTimeMillis())
        val src = LinkedHashMap<String, Set<String>>()
        var bundledCount = 0
        try {
            ctx.assets.open("blocklist.txt").use { ins ->
                BufferedReader(InputStreamReader(ins)).use { r ->
                    if (prefs.builtinEnabled()) {
                        val bundled = HashSet<String>()
                        while (true) {
                            val line = r.readLine() ?: break
                            for (d in Blocklist.parseLine(line)) if (bundled.add(d)) bundledCount++
                        }
                        src["bundled"] = bundled
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "bundled re-read failed", e)
        }
        synchronized(sourceCounts) {
            sourceCounts["bundled"] = bundledCount
        }

        val tally = Tally()
        for (cl in customLists()) {
            var n = 0
            var err: String? = null
            if (!cl.enabled) {
                synchronized(sourceCounts) { sourceCounts[cl.url] = 0 }
                synchronized(sourceErrors) { sourceErrors.remove(cl.url) }
                continue
            }
            try {
                val set = HashSet<String>()
                val kind = fetchList(cl.url, set)
                if (kind == KIND_UPDATED) {
                    // New content: swap the cache (old one replaced only on success).
                    writeCache(cl.url, set)
                    src[cl.url] = set
                    n = set.size
                    tally.updated++
                } else {
                    // 304 or identical body: cache on disk stays untouched.
                    if (kind == KIND_IDENTICAL) {
                        src[cl.url] = set
                        n = set.size
                    } else {
                        val cached = HashSet<String>()
                        n = readCache(cl.url, cached)
                        if (n > 0) src[cl.url] = cached
                        else {
                            // Meta says fresh but the cache is gone: drop the
                            // validators so the next check downloads in full.
                            err = "Cache hilang"
                            try { metaFile(cl.url).delete() } catch (_: Exception) {}
                        }
                    }
                    tally.unchanged++
                }
            } catch (e: Exception) {
                Log.w(TAG, "list check failed: " + cl.url, e)
                // fall back to disk cache so blocking keeps working offline
                val cached = HashSet<String>()
                n = readCache(cl.url, cached)
                if (n > 0) src[cl.url] = cached
                else err = e.javaClass.simpleName
                tally.failed++
            }
            synchronized(sourceCounts) { sourceCounts[cl.url] = n }
            synchronized(sourceErrors) {
                if (err != null) sourceErrors[cl.url] = err
                else sourceErrors.remove(cl.url)
            }
        }
        cleanStaleCache()
        blocklist.replaceSources(src)
        val now = System.currentTimeMillis()
        prefs.setLastListUpdate(now)
        prefs.setLastListStatusJson(statusJson(tally, now))
        prefs.setLastListStatus("")
        notifyChanged()
    }

    /** Raw outcome of the last refresh round, stored as data - never as a
     * finished sentence - so the Lists tab phrases it in the language
     * active when it is SHOWN. (Storing the finished sentence left
     * Indonesian text on screen in English mode until the next refresh.) */
    private fun statusJson(t: Tally, now: Long): String {
        val o = org.json.JSONObject()
        o.put("u", t.updated)
        o.put("n", t.unchanged)
        o.put("f", t.failed)
        o.put("ts", now)
        return o.toString()
    }

    // ---- disk cache for downloaded lists (survives restarts/updates) ----

    private fun cacheDir(): File {
        val d = File(ctx.filesDir, "blocklists")
        if (!d.exists()) d.mkdirs()
        return d
    }

    private fun writeCache(url: String, domains: Set<String>) {
        val f = File(cacheDir(), cacheName(url))
        try {
            BufferedWriter(FileWriter(f)).use { w ->
                for (d in domains) {
                    w.write(d)
                    w.newLine()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "cache write failed", e)
        }
    }

    /** @return number of domains read, 0 if no cache */
    private fun readCache(url: String, out: MutableSet<String>): Int {
        val f = File(cacheDir(), cacheName(url))
        if (!f.exists()) return 0
        var n = 0
        try {
            BufferedReader(FileReader(f)).use { r ->
                while (true) {
                    val line = r.readLine() ?: break
                    val t = line.trim()
                    if (t.isNotEmpty() && out.add(t)) n++
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "cache read failed", e)
        }
        return n
    }

    /** Delete cache files for lists that are no longer configured (incl. their .meta sidecars). */
    private fun cleanStaleCache() {
        val keep = HashSet<String>()
        for (cl in customLists()) {
            keep.add(cacheName(cl.url))
            keep.add(cacheName(cl.url) + META_SUFFIX)
        }
        val files = cacheDir().listFiles() ?: return
        for (f in files) {
            if (!keep.contains(f.name)) f.delete()
        }
    }

    /** Human-readable name for a blocklist source key ("bundled" or URL). */
    fun displayNameForSource(key: String): String {
        if ("bundled" == key) return "Built-in list"
        for (cl in customLists()) {
            if (cl.url == key) return if (cl.name.isEmpty()) key else cl.name
        }
        // fallback: host of URL
        try {
            val host = URL(key).host
            if (host.isNotEmpty()) return host
        } catch (ignored: Exception) {}
        return key
    }

    /** Validator snapshot for one list: stored beside its cache file. */
    private data class ListMeta(val etag: String, val lastMod: String, val hash: String)

    private fun metaFile(url: String): File = File(cacheDir(), cacheName(url) + META_SUFFIX)

    private fun readMeta(url: String): ListMeta? {
        val f = metaFile(url)
        if (!f.exists()) return null
        var etag = ""
        var lastMod = ""
        var hash = ""
        try {
            BufferedReader(FileReader(f)).use { r ->
                while (true) {
                    val line = r.readLine() ?: break
                    val i = line.indexOf('=')
                    if (i <= 0) continue
                    val v = line.substring(i + 1)
                    when (line.substring(0, i)) {
                        "etag" -> etag = v
                        "lastmod" -> lastMod = v
                        "hash" -> hash = v
                    }
                }
            }
            return ListMeta(etag, lastMod, hash)
        } catch (e: Exception) {
            Log.w(TAG, "meta read failed", e)
            return null
        }
    }

    private fun writeMeta(url: String, etag: String, lastMod: String, hash: String) {
        try {
            BufferedWriter(FileWriter(metaFile(url))).use { w ->
                w.write("etag=" + etag)
                w.newLine()
                w.write("lastmod=" + lastMod)
                w.newLine()
                w.write("hash=" + hash)
                w.newLine()
            }
        } catch (e: Exception) {
            Log.w(TAG, "meta write failed", e)
        }
    }

    /**
     * Conditional GET of one list, parsing its domains into [out].
     * - 304 → cache is fresh, nothing downloaded, cache file untouched.
     * - 200 → body is parsed; if its hash matches the cache, nothing is re-merged.
     * Never wipes the existing cache on error. Throws IOException on failure.
     *
     * @return KIND_UPDATED (new content) / KIND_UNCHANGED (304) / KIND_IDENTICAL (200, same bytes).
     */
    private fun fetchList(urlStr: String, out: MutableSet<String>): Int {
        val meta = readMeta(urlStr)
        val c = URL(urlStr).openConnection() as HttpURLConnection
        c.connectTimeout = 15000
        c.readTimeout = 30000
        c.setRequestProperty("User-Agent", "NetAverDNS/1.0")
        c.instanceFollowRedirects = true
        if (meta != null) {
            if (meta.etag.isNotEmpty()) c.setRequestProperty("If-None-Match", meta.etag)
            if (meta.lastMod.isNotEmpty()) c.setRequestProperty("If-Modified-Since", meta.lastMod)
        }
        val code: Int
        try {
            code = c.responseCode
        } catch (e: Exception) {
            c.disconnect()
            throw e
        }
        if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
            c.disconnect()
            return KIND_UNCHANGED
        }
        if (code != HttpURLConnection.HTTP_OK) {
            c.disconnect()
            throw IOException("HTTP $code")
        }
        val md = MessageDigest.getInstance("SHA-256")
        val newEtag = (c.getHeaderField("ETag") ?: "").trim()
        val newLastMod = (c.getHeaderField("Last-Modified") ?: "").trim()
        try {
            DigestInputStream(c.inputStream, md).use { dis ->
                BufferedReader(InputStreamReader(dis)).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        for (d in Blocklist.parseLine(line)) out.add(d)
                        if (out.size > 2_000_000) break // sanity cap, battery/memory guard
                    }
                }
            }
        } finally {
            c.disconnect()
        }
        val hash = md.digest().joinToString("") { "%02x".format(it) }
        writeMeta(urlStr, newEtag, newLastMod, hash)
        // Server ignored the validator but the bytes are identical: nothing to re-merge.
        if (meta != null && meta.hash.isNotEmpty() && meta.hash == hash) {
            return KIND_IDENTICAL
        }
        return KIND_UPDATED
    }

    fun customLists(): MutableList<CustomList> {
        val out = ArrayList<CustomList>()
        val raw = prefs.customListsRaw()
        for (part in raw.split(";")) {
            if (part.trim().isEmpty()) continue
            val f = part.split("|")
            if (f.size < 3) continue
            out.add(CustomList(f[0], f[1], "1" == f[2]))
        }
        return out
    }

    fun saveCustomLists(lists: List<CustomList>) {
        val sb = StringBuilder()
        for (cl in lists) {
            if (sb.isNotEmpty()) sb.append(';')
            sb.append(cl.name.replace("|", "").replace(";", ""))
                .append('|').append(cl.url.trim())
                .append('|').append(if (cl.enabled) "1" else "0")
        }
        prefs.setCustomListsRaw(sb.toString())
    }

    fun listInfos(): List<ListInfo> {
        val out = ArrayList<ListInfo>()
        synchronized(sourceCounts) {
            val b = sourceCounts["bundled"]
            out.add(ListInfo("Built-in Ads & Trackers", "bundled",
                prefs.builtinEnabled(), b ?: 0, null))
        }
        for (cl in customLists()) {
            val n: Int
            val err: String?
            synchronized(sourceCounts) {
                n = sourceCounts[cl.url] ?: 0
            }
            synchronized(sourceErrors) {
                err = sourceErrors[cl.url]
            }
            out.add(ListInfo(cl.name, cl.url, cl.enabled, n, err))
        }
        return out
    }

    companion object {
        private const val TAG = "BlocklistManager"

        /** Minimum gap between conditional auto-checks on VPN start. */
        private const val CHECK_MIN_MS = 3600_000L // 1 jam

        /** Sidecar file holding validators + content hash for each list cache. */
        private const val META_SUFFIX = ".meta"

        /** fetchList outcomes: new content / 304 / identical body despite 200. */
        private const val KIND_UPDATED = 0
        private const val KIND_UNCHANGED = 1
        private const val KIND_IDENTICAL = 2

        private fun cacheName(url: String): String {
            return try {
                val md = MessageDigest.getInstance("SHA-256")
                val h = md.digest(url.toByteArray(StandardCharsets.UTF_8))
                val sb = StringBuilder()
                for (b in h) sb.append(String.format("%02x", b))
                sb.toString() + ".txt"
            } catch (e: Exception) {
                Integer.toHexString(url.hashCode()) + ".txt"
            }
        }
    }
}
