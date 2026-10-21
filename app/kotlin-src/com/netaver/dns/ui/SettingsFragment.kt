package com.netaver.dns.ui

import android.app.Activity
import android.app.AlertDialog
import android.app.Fragment
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.dns.BlocklistManager
import com.netaver.dns.log.Entries
import com.netaver.dns.util.BackupManager
import com.netaver.dns.util.DebugCapture
import com.netaver.dns.util.Prefs

import org.json.JSONArray
import org.json.JSONObject

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Settings tab: battery + protection toggles. */
class SettingsFragment : Fragment() {
    private val debugHandler = Handler(Looper.getMainLooper())
    private var debugTicker: Runnable? = null
    private var logSizeTv: TextView? = null

    /** Refresh the "Ukuran log: X MB" label under Clear/Export (with row counts as a DB-health diagnostic). */
    private fun updateLogSize() {
        val act = activity ?: return
        val tv = logSizeTv ?: return
        try {
            val f = act.getDatabasePath("netaver_logs.db")
            val bytes = if (f.exists()) f.length() else 0L
            val mb = bytes / (1024.0 * 1024.0)
            val size = if (mb < 0.1) String.format("%d KB", bytes / 1024)
            else String.format("%.1f MB", mb)
            val app = act.application as NetAverApp
            val dnsN = app.logStore().dnsCount()
            val connN = app.logStore().connCount()
            tv.text = "Ukuran log: $size · DNS: $dnsN · Conn: $connN"
        } catch (e: Exception) {
            tv.text = "Ukuran log: —"
        }
    }

    override fun onResume() {
        super.onResume()
        updateLogSize()
    }

    /** Collapsible settings section: tap the header to show/hide the body. */
    private fun setupCollapsible(v: View, p: Prefs, headerId: Int, bodyId: Int,
                                 initial: Boolean, save: (Boolean) -> Unit, title: String) {
        val header: TextView = v.findViewById(headerId)
        val body: View = v.findViewById(bodyId)
        var collapsed = initial
        fun apply() {
            body.visibility = if (collapsed) View.GONE else View.VISIBLE
            header.text = "$title ${if (collapsed) "▸" else "▾"}"
        }
        header.setOnClickListener {
            collapsed = !collapsed
            save(collapsed)
            apply()
        }
        apply()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_settings, container, false)
        val act = activity!!
        val app = act.application as NetAverApp
        val p: Prefs = app.prefs()

        bind(v, R.id.sw_battery, p.batterySaver(), p::setBatterySaver)
        bind(v, R.id.sw_boot, p.startOnBoot(), p::setStartOnBoot)
        bind(v, R.id.sw_firewall, p.firewallEnabled(), p::setFirewallEnabled)
        bind(v, R.id.sw_bypass, p.blockBypass(), p::setBlockBypass)
        bind(v, R.id.sw_bypass_lan, p.bypassLan()) { checked -> p.setBypassLan(checked) }
        bind(v, R.id.sw_notif, p.showNotif(), p::setShowNotif)
        val geo: Switch = v.findViewById(R.id.sw_geoip)
        geo.isChecked = p.geoipEnabled()
        geo.setOnCheckedChangeListener { _, checked ->
            p.setGeoipEnabled(checked)
            app.geoIp().setEnabled(checked)
        }
        bind(v, R.id.sw_dnscache, p.dnsCacheEnabled(), p::setDnsCacheEnabled)

        val clear: Button = v.findViewById(R.id.btn_clear_logs)
        clear.setOnClickListener {
            AlertDialog.Builder(act)
                .setTitle(R.string.clear_logs)
                .setMessage(R.string.clear_logs_desc)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    app.logBus().clear()
                    updateLogSize()
                    Toast.makeText(act, "Logs cleared", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }

        val export: Button = v.findViewById(R.id.btn_export_logs)
        export.setOnClickListener { exportLogs() }

        logSizeTv = v.findViewById(R.id.log_size_label)
        updateLogSize()

        setupCollapsible(v, p, R.id.logs_header, R.id.logs_body,
            p.logsCollapsed(), p::setLogsCollapsed, "Logs")
        setupCollapsible(v, p, R.id.backup_header, R.id.backup_body,
            p.backupCollapsed(), p::setBackupCollapsed, "Backup")

        setupDebugButton(v, app)

        val expSet: Button = v.findViewById(R.id.btn_export_settings)
        expSet.setOnClickListener { exportSettings() }

        val impSet: Button = v.findViewById(R.id.btn_import_settings)
        impSet.setOnClickListener {
            val i = Intent(Intent.ACTION_OPEN_DOCUMENT)
            i.addCategory(Intent.CATEGORY_OPENABLE)
            i.type = "*/*"
            startActivityForResult(i, REQ_IMPORT_SETTINGS)
        }

        val split: Button = v.findViewById(R.id.btn_split_tunnel)
        split.setOnClickListener {
            if (activity is MainActivity) {
                (activity as MainActivity).openSplitTunnel()
            }
        }

        // version footer: always reflect the real installed version
        try {
            val ver: TextView = v.findViewById(R.id.version_label)
            val vn = act.packageManager
                .getPackageInfo(act.packageName, 0).versionName
            ver.text = "NetAver DNS v$vn · lightweight build"
        } catch (ignored: Exception) {
        }
        return v
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val act = activity ?: return
        if (requestCode != REQ_IMPORT_SETTINGS || resultCode != Activity.RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val input = act.contentResolver.openInputStream(uri)
                ?: throw Exception("cannot open file")
            input.use { ins ->
                val buf = ByteArrayOutputStream()
                val tmp = ByteArray(8192)
                var n: Int
                while (ins.read(tmp).also { n = it } > 0) {
                    buf.write(tmp, 0, n)
                    if (buf.size() > 2_000_000) throw Exception("file too large")
                }
                val app = act.application as NetAverApp
                val result = BackupManager.importJson(app,
                    buf.toString(StandardCharsets.UTF_8.name()))
                Toast.makeText(act, result, Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(act, "Import failed: ${e.message}",
                Toast.LENGTH_LONG).show()
        }
    }

    /** Export all settings as JSON into Download, then offer to share it. */
    private fun exportSettings() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val json: String
        try {
            json = BackupManager.export(app)
        } catch (e: Exception) {
            Toast.makeText(act, "Export failed: ${e.message}",
                Toast.LENGTH_LONG).show()
            return
        }
        val name = "netaver-dns-settings-" +
            SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) + ".json"
        try {
            val cv = ContentValues()
            cv.put(MediaStore.Downloads.DISPLAY_NAME, name)
            cv.put(MediaStore.Downloads.MIME_TYPE, "application/json")
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            val uri: Uri = act.contentResolver
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
                ?: throw Exception("MediaStore insert failed")
            act.contentResolver.openOutputStream(uri).use { out ->
                if (out == null) throw Exception("openOutputStream failed")
                out.write(json.toByteArray(StandardCharsets.UTF_8))
            }
            Toast.makeText(act, "Saved to Download/$name", Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "application/json"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, "Share settings"))
        } catch (e: Exception) {
            Toast.makeText(act, "Export failed: ${e.message}",
                Toast.LENGTH_LONG).show()
        }
    }

    /** Debug capture: record everything, then share the JSON report for analysis. */
    private fun setupDebugButton(v: View, app: NetAverApp) {
        val btn: Button = v.findViewById(R.id.btn_debug)
        refreshDebugBtn(btn, app)
        btn.setOnClickListener {
            val dc: DebugCapture = app.debugCapture()
            if (dc.isCapturing()) {
                stopAndShareDebug(app)
            } else {
                dc.start(buildDebugConfig(app))
                Toast.makeText(activity,
                    "Debug capture started — reproduce the issue, then tap Stop",
                    Toast.LENGTH_LONG).show()
            }
            refreshDebugBtn(btn, app)
        }
        debugTicker = Runnable {
            val act = activity ?: return@Runnable
            if (app.debugCapture().isCapturing()) {
                refreshDebugBtn(btn, app)
                debugTicker?.let { debugHandler.postDelayed(it, 1000) }
            }
        }
        debugTicker?.let { debugHandler.postDelayed(it, 1000) }
    }

    private fun refreshDebugBtn(btn: Button, app: NetAverApp) {
        val dc: DebugCapture = app.debugCapture()
        if (dc.isCapturing()) {
            val secs = (System.currentTimeMillis() - dc.getStartTime()) / 1000
            btn.text = String.format(Locale.US, "Stop & share debug (%d:%02d)",
                secs / 60, secs % 60)
        } else {
            btn.text = "Start debug capture"
        }
    }

    private fun buildDebugConfig(app: NetAverApp): JSONObject {
        val c = JSONObject()
        try {
            val p: Prefs = app.prefs()
            val ver: String = try {
                val act = activity ?: throw Exception("no activity")
                act.packageManager.getPackageInfo(act.packageName, 0).versionName
            } catch (e: Exception) {
                "?"
            }
            c.put("app_version", ver)
            c.put("android", Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")")
            c.put("upstream_preset", p.getUpstream())
            c.put("upstream_custom", p.customUpstream())
            c.put("upstream_list", p.upstreamList().joinToString(";"))
            c.put("upstream_mode", p.upstreamModeName())
            c.put("protocol", if (p.getProtocol() == 2) "DoH" else "DoT")
            c.put("block_bypass", p.blockBypass())
            c.put("bypass_lan", p.bypassLan())
            c.put("dns_cache", p.dnsCacheEnabled())
            c.put("firewall_blocked_apps", app.firewall().blockedCount())
            c.put("custom_rules", app.customRules().count())
            c.put("split_tunnel_apps", p.splitBypassSet().size)
            val lists = JSONArray()
            for (li in app.blocklists().listInfos()) {
                val l = JSONObject()
                l.put("name", li.name)
                l.put("enabled", li.enabled)
                l.put("rules", li.rules)
                if (li.error != null) l.put("error", li.error)
                lists.put(l)
            }
            c.put("blocklists", lists)
        } catch (ignored: Exception) {
        }
        return c
    }

    private fun stopAndShareDebug(app: NetAverApp) {
        val act = activity ?: return
        val report: JSONObject = app.debugCapture().stop()
        val name = "netaver-debug-" +
            SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) + ".json"
        try {
            val cv = ContentValues()
            cv.put(MediaStore.Downloads.DISPLAY_NAME, name)
            cv.put(MediaStore.Downloads.MIME_TYPE, "application/json")
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            val uri: Uri = act.contentResolver
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
                ?: throw Exception("MediaStore insert failed")
            act.contentResolver.openOutputStream(uri).use { out ->
                if (out == null) throw Exception("openOutputStream failed")
                out.write(report.toString(1).toByteArray(StandardCharsets.UTF_8))
            }
            Toast.makeText(act, "Saved to Download/$name", Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "application/json"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, "Share debug"))
        } catch (e: Exception) {
            Toast.makeText(act, "Debug export failed: ${e.message}",
                Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroyView() {
        debugTicker?.let { debugHandler.removeCallbacks(it) }
        super.onDestroyView()
    }

    private fun bind(root: View, id: Int, initial: Boolean, setter: (Boolean) -> Unit) {
        val sw: Switch = root.findViewById(id)
        sw.isChecked = initial
        sw.setOnCheckedChangeListener { _, checked -> setter(checked) }
    }

    /** Export DNS + connection logs as CSV into Download, then offer to share it. */
    private fun exportLogs() {
        val act = activity ?: return
        val app = act.application as NetAverApp
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val sb = StringBuilder()
        sb.append("time,domain,qtype,app,blocked,latency_ms,resolved_ip,country,matched\n")
        val dns = app.logBus().dnsSnapshot()
        for (d in dns) {
            sb.append(fmt.format(Date(d.time))).append(',')
                .append(csv(d.domain)).append(',')
                .append(csv(d.qtype)).append(',')
                .append(csv(d.app)).append(',')
                .append(if (d.blocked) "1" else "0").append(',')
                .append(d.latencyMs).append(',')
                .append(csv(d.resolvedIp)).append(',')
                .append(csv(d.countryCode)).append(',')
                .append(csv(d.matchInfo)).append('\n')
        }
        sb.append("\n# connections\ntime,app,proto,dest,blocked,bytes_up,bytes_down,country\n")
        for (c in app.logBus().connSnapshot()) {
            sb.append(fmt.format(Date(c.time))).append(',')
                .append(csv(c.app)).append(',')
                .append(csv(c.proto)).append(',')
                .append(csv(c.dest)).append(',')
                .append(if (c.blocked) "1" else "0").append(',')
                .append(c.bytesUp).append(',')
                .append(c.bytesDown).append(',')
                .append(csv(c.countryCode)).append('\n')
        }
        if (dns.isEmpty()) {
            Toast.makeText(act, "No logs to export", Toast.LENGTH_SHORT).show()
            return
        }
        val name = "netaver-dns-log-" +
            SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) + ".csv"
        try {
            val cv = ContentValues()
            cv.put(MediaStore.Downloads.DISPLAY_NAME, name)
            cv.put(MediaStore.Downloads.MIME_TYPE, "text/csv")
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            val uri: Uri = act.contentResolver
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
                ?: throw Exception("MediaStore insert failed")
            act.contentResolver.openOutputStream(uri).use { out ->
                if (out == null) throw Exception("openOutputStream failed")
                out.write(sb.toString().toByteArray(StandardCharsets.UTF_8))
            }
            Toast.makeText(act, "Saved to Download/$name", Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "text/csv"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, "Share log"))
        } catch (e: Exception) {
            Toast.makeText(act, "Export failed: ${e.message}",
                Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        private const val REQ_IMPORT_SETTINGS = 2001

        private fun csv(s: String?): String {
            if (s == null) return ""
            if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
                return "\"" + s.replace("\"", "\"\"") + "\""
            }
            return s
        }
    }
}
