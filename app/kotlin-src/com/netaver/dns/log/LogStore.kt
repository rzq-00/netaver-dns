package com.netaver.dns.log

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build

import com.netaver.dns.R
import com.netaver.dns.ui.MainActivity

import java.io.File
import java.util.ArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * SQLite backing store for logs. All writes go through a single background
 * thread — never on the packet path. The UI keeps reading the in-memory
 * rings in LogBus; this store only makes them survive app restarts/updates.
 *
 * Battery-friendly design (v1.4.11):
 * - inserts are queued and flushed in ONE SQLite transaction every 2s
 *   (a single transaction avoids an fsync per row — the dominant cost
 *   during heavy browsing);
 * - prune runs at most once per 60s with a cheap indexed range delete
 *   instead of a NOT IN subquery every 200 rows.
 *
 * Keeps a week of history (age-pruned, count caps as backstop);
 * search covers the full stored history, not just the in-memory rings.
 */
class LogStore(ctx: Context) : SQLiteOpenHelper(ctx.applicationContext, DB, null, VER) {

    companion object {
        private const val DB = "netaver_logs.db"
        private const val VER = 3
        private const val CAP_DNS = 3000
        private const val CAP_CONN = 1500
        private const val RESTORE_DNS = 1000
        private const val RESTORE_CONN = 500
        private const val FLUSH_MS = 2000L
        private const val PRUNE_MIN_MS = 60_000L
        /** Log retention: entries older than this are pruned. */
        private const val RETENTION_MS = 7L * 24 * 60 * 60 * 1000 // 1 week
        /** Warn the user when the log DB reaches this size (at most once/day). */
        private const val WARN_BYTES = 25L * 1024 * 1024 // 25 MB
        private const val WARN_MIN_MS = 24L * 60 * 60 * 1000 // 1 day
        private const val WARN_CHANNEL = "netaver_log_warn"
        private const val WARN_NOTIF_ID = 3

        private const val OP_DNS = 1
        private const val OP_CONN = 2
        private const val OP_COUNTRY = 3

        private fun str(c: Cursor, i: Int): String = c.getString(i) ?: ""
    }

    private class Op {
        var type: Int = 0
        var dns: Entries.DnsEntry? = null
        var conn: Entries.ConnEntry? = null
        var ip: String? = null
        var cc: String? = null
    }

    private val io: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "logstore").apply { isDaemon = true }
        }

    private val appCtx: Context = ctx.applicationContext

    /** Only touched on the io thread. */
    private val pending = ArrayList<Op>()
    private var lastPruneMs = 0L

    init {
        io.scheduleWithFixedDelay(
            this::flushLocked, FLUSH_MS, FLUSH_MS,
            TimeUnit.MILLISECONDS
        )
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE dns_log(_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "time INTEGER,domain TEXT,qtype TEXT,app TEXT,uid INTEGER,"
                + "blocked INTEGER,latency INTEGER,ip TEXT,country TEXT,match TEXT,"
                + "bypass INTEGER DEFAULT 0)"
        )
        db.execSQL(
            "CREATE TABLE conn_log(_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "time INTEGER,app TEXT,uid INTEGER,proto TEXT,dest TEXT,"
                + "up INTEGER,down INTEGER,dur INTEGER,blocked INTEGER,country TEXT)"
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_log(time)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_conn_time ON conn_log(time)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {
        // v2: bypass flag for the "Bypass" log filter
        if (oldV < 2) {
            try {
                db.execSQL("ALTER TABLE dns_log ADD COLUMN bypass INTEGER DEFAULT 0")
            } catch (_: Exception) {
            }
        }
        // v3: time indexes for cheap age-based prune
        if (oldV < 3) {
            try {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_log(time)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_conn_time ON conn_log(time)")
            } catch (_: Exception) {
            }
        }
    }

    /** Queue an insert (call from anywhere). Flushed in batches. */
    fun saveDns(e: Entries.DnsEntry) {
        io.execute {
            val o = Op()
            o.type = OP_DNS
            o.dns = e
            pending.add(o)
        }
    }

    /** Queue an insert (call from anywhere). Flushed in batches. */
    fun saveConn(e: Entries.ConnEntry) {
        io.execute {
            val o = Op()
            o.type = OP_CONN
            o.conn = e
            pending.add(o)
        }
    }

    /**
     * Fill in country codes that resolved after the insert (GeoIp is async).
     * Queued in order behind the corresponding saveDns/saveConn so the row
     * exists when the UPDATE runs.
     */
    fun updateCountry(ip: String?, cc: String?) {
        if (ip.isNullOrEmpty() || cc.isNullOrEmpty()) return
        io.execute {
            val o = Op()
            o.type = OP_COUNTRY
            o.ip = ip
            o.cc = cc
            pending.add(o)
        }
    }

    /** Total (queries, blocked) over ALL stored DNS history. BLOCKING — call off the main thread. */
    fun countAll(): LongArray {
        var q = 0L
        var b = 0L
        try {
            val db = readableDatabase
            db.rawQuery("SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM dns_log", null).use { c ->
                if (c.moveToFirst()) {
                    q = c.getLong(0)
                    b = c.getLong(1)
                }
            }
        } catch (ignored: Exception) {
        }
        return longArrayOf(q, b)
    }

    /**
     * Load recent entries, oldest-first (ring order). BLOCKING — call off the
     * main thread (e.g. at app start).
     */
    fun loadRecent(dnsOut: MutableList<Entries.DnsEntry>, connOut: MutableList<Entries.ConnEntry>) {
        try {
            val db = readableDatabase
            db.rawQuery(
                "SELECT time,domain,qtype,app,uid,blocked,latency,ip,country,match,bypass"
                    + " FROM dns_log ORDER BY _id DESC LIMIT $RESTORE_DNS",
                null
            ).use { c ->
                while (c.moveToNext()) {
                    val e = Entries.DnsEntry(
                        c.getLong(0), str(c, 1), str(c, 2), str(c, 3), c.getInt(4),
                        c.getInt(5) == 1, c.getLong(6), str(c, 7)
                    )
                    e.countryCode = str(c, 8)
                    e.matchInfo = str(c, 9)
                    e.isBypass = c.getInt(10) == 1
                    dnsOut.add(e)
                }
            }
            dnsOut.reverse()
            db.rawQuery(
                "SELECT time,app,uid,proto,dest,up,down,dur,blocked,country"
                    + " FROM conn_log ORDER BY _id DESC LIMIT $RESTORE_CONN",
                null
            ).use { c ->
                while (c.moveToNext()) {
                    val e = Entries.ConnEntry(
                        c.getLong(0), str(c, 1), c.getInt(2), str(c, 3), str(c, 4),
                        c.getLong(5), c.getLong(6), c.getLong(7), c.getInt(8) == 1
                    )
                    e.countryCode = str(c, 9)
                    connOut.add(e)
                }
            }
            connOut.reverse()
        } catch (_: Exception) {
        }
    }

    /** Flush pending writes, then delete all stored logs. Async. */
    fun clear() {
        io.execute {
            try {
                flushLocked()
                val db = writableDatabase
                db.delete("dns_log", null, null)
                db.delete("conn_log", null, null)
            } catch (_: Exception) {
            }
        }
    }

    /** Runs on the io thread only. */
    private fun flushLocked() {
        if (pending.isEmpty()) return
        try {
            val db = writableDatabase
            db.beginTransaction()
            try {
                for (i in 0 until pending.size) {
                    val o = pending[i]
                    if (o.type == OP_DNS) insertDns(db, o.dns!!)
                    else if (o.type == OP_CONN) insertConn(db, o.conn!!)
                    else applyCountry(db, o.ip!!, o.cc!!)
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
            pending.clear()
            maybePrune(db)
        } catch (_: Exception) {
        }
    }

    private fun insertDns(db: SQLiteDatabase, e: Entries.DnsEntry) {
        val v = ContentValues()
        v.put("time", e.time)
        v.put("domain", e.domain)
        v.put("qtype", e.qtype)
        v.put("app", e.app)
        v.put("uid", e.uid)
        v.put("blocked", if (e.blocked) 1 else 0)
        v.put("latency", e.latencyMs)
        v.put("ip", e.resolvedIp)
        v.put("country", e.countryCode)
        v.put("match", e.matchInfo)
        v.put("bypass", if (e.isBypass) 1 else 0)
        db.insert("dns_log", null, v)
    }

    private fun insertConn(db: SQLiteDatabase, e: Entries.ConnEntry) {
        val v = ContentValues()
        v.put("time", e.time)
        v.put("app", e.app)
        v.put("uid", e.uid)
        v.put("proto", e.proto)
        v.put("dest", e.dest)
        v.put("up", e.bytesUp)
        v.put("down", e.bytesDown)
        v.put("dur", e.durationMs)
        v.put("blocked", if (e.blocked) 1 else 0)
        v.put("country", e.countryCode)
        db.insert("conn_log", null, v)
    }

    private fun applyCountry(db: SQLiteDatabase, ip: String, cc: String) {
        val v = ContentValues()
        v.put("country", cc)
        db.update(
            "dns_log", v, "ip=? AND (country IS NULL OR country='')",
            arrayOf(ip)
        )
        // conn dest is "ip:port"; IPs contain no LIKE wildcards
        db.update(
            "conn_log", v, "dest LIKE ? AND (country IS NULL OR country='')",
            arrayOf("$ip:%")
        )
    }

    /**
     * Cheap prune: at most once per minute.
     * Primary rule is AGE (1 week retention, indexed range delete);
     * the count caps stay as a backstop for pathological bursts.
     */
    private fun maybePrune(db: SQLiteDatabase) {
        val now = System.currentTimeMillis()
        if (now - lastPruneMs < PRUNE_MIN_MS) return
        lastPruneMs = now
        try {
            val cutoff = now - RETENTION_MS
            db.execSQL("DELETE FROM dns_log WHERE time < $cutoff")
            db.execSQL("DELETE FROM conn_log WHERE time < $cutoff")
            db.execSQL(
                "DELETE FROM dns_log WHERE _id <= "
                    + "(SELECT MAX(_id) - $CAP_DNS FROM dns_log)"
            )
            db.execSQL(
                "DELETE FROM conn_log WHERE _id <= "
                    + "(SELECT MAX(_id) - $CAP_CONN FROM conn_log)"
            )
            checkSizeWarning()
        } catch (_: Exception) {
        }
    }

    /**
     * Search the full stored history (not just the in-memory rings).
     * BLOCKING — call off the main thread.
     *
     * @param q lowercase search text; matched against domain/ip/app/match
     * @param filter 0=all 1=blocked 2=allowed 3=bypass
     */
    fun searchDns(q: String, filter: Int, limit: Int): List<Entries.DnsEntry> {
        val out = ArrayList<Entries.DnsEntry>()
        try {
            val db = readableDatabase
            val like = "%" + q.replace("\\", "\\\\")
                .replace("%", "\\%").replace("_", "\\_") + "%"
            var where = ("(LOWER(domain) LIKE ? ESCAPE '\'"
                + " OR LOWER(ip) LIKE ? ESCAPE '\'"
                + " OR LOWER(app) LIKE ? ESCAPE '\'"
                + " OR LOWER(match) LIKE ? ESCAPE '\'")
            if (filter == 1) where += " AND blocked=1"
            else if (filter == 2) where += " AND blocked=0"
            else if (filter == 3) where += " AND bypass=1"
            val args = arrayOf(like, like, like, like)
            db.rawQuery(
                "SELECT time,domain,qtype,app,uid,blocked,latency,ip,country,match,bypass"
                    + " FROM dns_log WHERE " + where
                    + " ORDER BY _id DESC LIMIT " + limit.coerceIn(1, 1000),
                args
            ).use { c ->
                while (c.moveToNext()) {
                    val e = Entries.DnsEntry(
                        c.getLong(0), str(c, 1), str(c, 2), str(c, 3), c.getInt(4),
                        c.getInt(5) == 1, c.getLong(6), str(c, 7)
                    )
                    e.countryCode = str(c, 8)
                    e.matchInfo = str(c, 9)
                    e.isBypass = c.getInt(10) == 1
                    out.add(e)
                }
            }
        } catch (_: Exception) {
        }
        return out
    }

    /** Rows in dns_log, or -1 when the read fails (diagnostic for Settings). */
    fun dnsCount(): Long {
        return try {
            readableDatabase.rawQuery("SELECT COUNT(*) FROM dns_log", null).use { c ->
                if (c.moveToFirst()) c.getLong(0) else -1L
            }
        } catch (_: Exception) {
            -1L
        }
    }

    /** Rows in conn_log, or -1 when the read fails (diagnostic for Settings). */
    fun connCount(): Long {
        return try {
            readableDatabase.rawQuery("SELECT COUNT(*) FROM conn_log", null).use { c ->
                if (c.moveToFirst()) c.getLong(0) else -1L
            }
        } catch (_: Exception) {
            -1L
        }
    }

    /** Warn at most once/day when the log DB grows past WARN_BYTES. */
    private fun checkSizeWarning() {        try {
            val f: File = appCtx.getDatabasePath(DB)
            if (!f.exists() || f.length() < WARN_BYTES) return
            val sp = appCtx.getSharedPreferences("sunraku_dns", Context.MODE_PRIVATE)
            val now = System.currentTimeMillis()
            if (now - sp.getLong("log_size_warned_at", 0) < WARN_MIN_MS) return
            sp.edit().putLong("log_size_warned_at", now).apply()

            val nm = appCtx.getSystemService(NotificationManager::class.java) ?: return
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(NotificationChannel(
                    WARN_CHANNEL, "Peringatan Log",
                    NotificationManager.IMPORTANCE_DEFAULT))
            }
            val openIntent = Intent(appCtx, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val pi = PendingIntent.getActivity(
                appCtx, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val mb = f.length() / (1024 * 1024)
            val nb = Notification.Builder(appCtx, WARN_CHANNEL)
                .setContentTitle("Log NetAver membesar")
                .setContentText("Ukuran log ${mb}MB — pertimbangkan Clear log di Pengaturan")
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(pi)
                .setAutoCancel(true)
            if (Build.VERSION.SDK_INT >= 26) nb.setChannelId(WARN_CHANNEL)
            nm.notify(WARN_NOTIF_ID, nb.build())
        } catch (_: Exception) {
        }
    }
}
