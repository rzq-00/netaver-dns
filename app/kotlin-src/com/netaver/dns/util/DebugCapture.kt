package com.netaver.dns.util

import com.netaver.dns.log.Entries

import org.json.JSONArray
import org.json.JSONObject

import java.text.SimpleDateFormat
import java.util.ArrayList
import java.util.Date
import java.util.Locale

/**
 * In-memory debug capture for analysis. While active, every DNS query,
 * connection and notable service event is recorded (capped). On stop a
 * JSON report is produced for export/share.
 */
class DebugCapture {
    private var capturing = false
    private var startTime = 0L
    private var config: JSONObject? = null
    private val events = ArrayList<JSONObject>()
    private var truncated = false

    companion object {
        private const val MAX_EVENTS = 8000

        // SimpleDateFormat is not thread-safe; ts() is called from DNS workers,
        // the selector thread and the tun thread concurrently.
        private val TS = ThreadLocal.withInitial {
            SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
        }

        private fun ts(t: Long): String = TS.get().format(Date(t))
    }

    @Synchronized
    fun start(config: JSONObject?) {
        events.clear()
        truncated = false
        this.config = config
        startTime = System.currentTimeMillis()
        capturing = true
        event("capture_start", "debug capture started")
    }

    @Synchronized
    fun isCapturing(): Boolean = capturing

    @Synchronized
    fun getStartTime(): Long = startTime

    @Synchronized
    private fun add(o: JSONObject) {
        if (!capturing) return
        if (events.size >= MAX_EVENTS) {
            truncated = true
            return
        }
        events.add(o)
    }

    fun onDns(e: Entries.DnsEntry) {
        try {
            val o = JSONObject()
            o.put("t", "dns")
            o.put("ts", ts(e.time))
            o.put("app", e.app)
            o.put("domain", e.domain)
            o.put("qtype", e.qtype)
            o.put("blocked", e.blocked)
            o.put("bypass", e.isBypass)
            o.put("latency_ms", e.latencyMs)
            o.put("ip", e.resolvedIp)
            o.put("match", e.matchInfo)
            o.put("cc", e.countryCode)
            add(o)
        } catch (_: Exception) {
        }
    }

    fun onConn(e: Entries.ConnEntry) {
        try {
            val o = JSONObject()
            o.put("t", "conn")
            o.put("ts", ts(e.time))
            o.put("app", e.app)
            o.put("proto", e.proto)
            o.put("dest", e.dest)
            o.put("blocked", e.blocked)
            o.put("up", e.bytesUp)
            o.put("down", e.bytesDown)
            o.put("dur_ms", e.durationMs)
            add(o)
        } catch (_: Exception) {
        }
    }

    /** Logged when a connection/session starts; lets hangs show up even if never closed. */
    fun connStart(app: String?, proto: String?, dest: String?) {
        try {
            val o = JSONObject()
            o.put("t", "conn_start")
            o.put("ts", ts(System.currentTimeMillis()))
            o.put("app", app ?: "")
            o.put("proto", proto)
            o.put("dest", dest)
            add(o)
        } catch (_: Exception) {
        }
    }

    fun event(tag: String, detail: String?) {
        try {
            val o = JSONObject()
            o.put("t", "event")
            o.put("ts", ts(System.currentTimeMillis()))
            o.put("tag", tag)
            o.put("detail", detail ?: "")
            add(o)
        } catch (_: Exception) {
        }
    }

    /** Stops capture and returns the full report. */
    @Synchronized
    fun stop(): JSONObject {
        event("capture_stop", "debug capture stopped")
        capturing = false
        val report = JSONObject()
        try {
            report.put("app", "NetAver DNS")
            report.put(
                "capture_started", SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss", Locale.US
                ).format(Date(startTime))
            )
            report.put("duration_ms", System.currentTimeMillis() - startTime)
            report.put("truncated", truncated)
            report.put("config", config ?: JSONObject())
            val arr = JSONArray()
            for (e in events) arr.put(e)
            report.put("events", arr)
            report.put("event_count", events.size)
        } catch (_: Exception) {
        }
        return report
    }
}
