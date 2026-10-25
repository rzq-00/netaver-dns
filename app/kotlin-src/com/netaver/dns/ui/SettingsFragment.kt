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
import android.widget.EditText
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
import com.netaver.dns.util.UpdateChecker
import com.netaver.dns.util.Updater

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
    private var updateStatusTv: TextView? = null

    /** "Update available: vX" line under the current-version row. */
    private fun refreshUpdateStatus() {
        val act = activity ?: return
        val tv = updateStatusTv ?: return
        val app = act.application as NetAverApp
        val avail = app.prefs().updateAvailable()
        if (avail.isNotEmpty() && UpdateChecker.isNewer(avail,
                Updater(act).installedVersion())) {
            tv.text = getString(R.string.update_available_fmt, avail)
            tv.visibility = View.VISIBLE
        } else {
            tv.visibility = View.GONE
        }
    }

    /** Refresh the "Ukuran log: X MB" label under Clear/Export (with row counts as a DB-health diagnostic). */
    private fun updateLogSize() {
        val act = activity ?: return
        val tv = logSizeTv ?: return
        try {
            val f = act.getDatabasePath("netaver_logs.db")
            val bytes = if (f.exists()) f.length() else 0L
            val mb = bytes / (1024.0 * 1024.0)
            val size = if (mb < 0.1) String.format(Locale.US, "%d KB", bytes / 1024)
            else String.format(Locale.US, "%.1f MB", mb)
            val app = act.application as NetAverApp
            val dnsN = app.logStore().dnsCount()
            val connN = app.logStore().connCount()
            tv.text = getString(R.string.log_size_fmt, size, dnsN, connN)
        } catch (e: Exception) {
            tv.setText(R.string.log_size_unknown)
        }
    }

    override fun onResume() {
        super.onResume()
        updateLogSize()
        refreshUpdateStatus()
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

        // ---- DNS cache section ----
        // stored-answer count on the Clear cache row
        val cacheCount: TextView = v.findViewById(R.id.cache_count)
        cacheCount.text = getString(R.string.cache_entries_fmt, app.dnsCache().size())
        v.findViewById<View>(R.id.set_cache_clear).setOnClickListener {
            app.dnsCache().clear()
            cacheCount.text = getString(R.string.cache_entries_fmt, 0)
            Toast.makeText(act, R.string.cache_cleared, Toast.LENGTH_SHORT).show()
        }
        bind(v, R.id.sw_optimistic, p.cacheOptimistic()) { checked ->
            p.setCacheOptimistic(checked)
            app.dnsCache().configure(p.cacheMinTtlSec(), p.cacheOptimistic(), p.cacheMaxEntries())
        }
        // minimum TTL override: manual seconds, with the staleness warning
        val minTtlValue: TextView = v.findViewById(R.id.cache_min_ttl_value)
        fun minTtlLabel(): String =
            if (p.cacheMinTtlSec() <= 0) getString(R.string.cache_value_off)
            else getString(R.string.cache_seconds_fmt, p.cacheMinTtlSec())
        minTtlValue.text = minTtlLabel()
        v.findViewById<View>(R.id.set_cache_min_ttl).setOnClickListener {
            val input = EditText(act)
            input.inputType = android.text.InputType.TYPE_CLASS_NUMBER
            input.setText(p.cacheMinTtlSec().toString())
            input.setSelection(input.text.length)
            AlertDialog.Builder(act)
                .setTitle(R.string.cache_min_ttl)
                .setMessage(R.string.cache_min_ttl_warn)
                .setView(input)
                .setPositiveButton(R.string.save) { _, _ ->
                    val sec = input.text.toString().trim().toIntOrNull()
                    if (sec == null || sec < 0 || sec > 86400) {
                        Toast.makeText(act, R.string.cache_min_ttl_invalid, Toast.LENGTH_LONG).show()
                    } else {
                        p.setCacheMinTtlSec(sec)
                        app.dnsCache().configure(p.cacheMinTtlSec(), p.cacheOptimistic(), p.cacheMaxEntries())
                        app.dnsCache().clear() // stored answers were cached under the old floor
                        minTtlValue.text = minTtlLabel()
                        cacheCount.text = getString(R.string.cache_entries_fmt, 0)
                    }
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }

        // ---- Advanced settings (access key: hiding never disables a feature) ----
        val advBody: View = v.findViewById(R.id.advanced_body)
        val advSw: Switch = v.findViewById(R.id.sw_advanced)
        advSw.isChecked = p.advancedSettings()
        advBody.visibility = if (p.advancedSettings()) View.VISIBLE else View.GONE
        advSw.setOnCheckedChangeListener { _, checked ->
            p.setAdvancedSettings(checked)
            advBody.visibility = if (checked) View.VISIBLE else View.GONE
        }
        bind(v, R.id.sw_cache_flush, p.cacheFlushOnNetworkChange(), p::setCacheFlushOnNetworkChange)
        bind(v, R.id.sw_show_system, p.showSystemApps(), p::setShowSystemApps)

        // maximum cache size (entries)
        val cacheMaxValue: TextView = v.findViewById(R.id.cache_max_value)
        val cacheMaxChoices = intArrayOf(500, 1000, 2000, 5000)
        cacheMaxValue.text = getString(R.string.cache_entries_value_fmt, p.cacheMaxEntries())
        v.findViewById<View>(R.id.set_cache_max).setOnClickListener {
            // U4: include the current value when an import set a non-preset
            // size (e.g. 3000) — otherwise indexOf misses it and the dialog
            // preselects 500 while the row label shows the real value.
            val choices = (cacheMaxChoices.toList() + p.cacheMaxEntries()).distinct().sorted()
            val labels = choices.map {
                getString(R.string.cache_entries_value_fmt, it)
            }.toTypedArray()
            val cur = choices.indexOf(p.cacheMaxEntries()).coerceAtLeast(0)
            showChoice(R.string.cache_max_size, labels, cur) { which ->
                p.setCacheMaxEntries(choices[which])
                app.dnsCache().configure(p.cacheMinTtlSec(), p.cacheOptimistic(), p.cacheMaxEntries())
                cacheMaxValue.text = getString(R.string.cache_entries_value_fmt, p.cacheMaxEntries())
            }
        }

        // blocklist check interval (hours)
        val blistValue: TextView = v.findViewById(R.id.blist_interval_value)
        val blistChoices = intArrayOf(1, 6, 12, 24)
        fun blistLabel(h: Int): String =
            if (h == 1) getString(R.string.blist_hour_one) else getString(R.string.blist_hours_fmt, h)
        blistValue.text = blistLabel(p.blocklistCheckIntervalHours())
        v.findViewById<View>(R.id.set_blist_interval).setOnClickListener {
            // U-N2: same U4 treatment as the cache-size dialog — include
            // the current value when an import set a non-preset interval
            // (e.g. 3h), or indexOf misses it and the dialog preselects
            // 1h while the row label shows the real value.
            val choices = (blistChoices.toList() + p.blocklistCheckIntervalHours()).distinct().sorted()
            val labels = choices.map { blistLabel(it) }.toTypedArray()
            val cur = choices.indexOf(p.blocklistCheckIntervalHours()).coerceAtLeast(0)
            showChoice(R.string.blist_interval, labels, cur) { which ->
                p.setBlocklistCheckIntervalHours(choices[which])
                blistValue.text = blistLabel(p.blocklistCheckIntervalHours())
            }
        }

        // logging mode (full / DNS only / minimal)
        val logModeValue: TextView = v.findViewById(R.id.logging_mode_value)
        val logModeLabels = arrayOf(
            getString(R.string.logging_mode_full),
            getString(R.string.logging_mode_dns),
            getString(R.string.logging_mode_minimal))
        logModeValue.text = logModeLabels[p.loggingMode()]
        v.findViewById<View>(R.id.set_logging_mode).setOnClickListener {
            showChoice(R.string.logging_mode, logModeLabels, p.loggingMode()) { which ->
                p.setLoggingMode(which)
                app.logBus().setLoggingMode(which)
                logModeValue.text = logModeLabels[which]
            }
        }

        // log retention (days)
        val retentionValue: TextView = v.findViewById(R.id.log_retention_value)
        val retentionChoices = intArrayOf(1, 3, 7, 30)
        fun retentionLabel(d: Int): String =
            if (d == 1) getString(R.string.retention_day_one)
            else getString(R.string.retention_days_fmt, d)
        retentionValue.text = retentionLabel(p.logRetentionDays())
        v.findViewById<View>(R.id.set_log_retention).setOnClickListener {
            // U-N2: same U4 treatment as the cache-size dialog — include
            // the current value when an import set a non-preset
            // retention (e.g. 5 days), or the dialog preselects 1 day
            // while the row label shows the real value.
            val choices = (retentionChoices.toList() + p.logRetentionDays()).distinct().sorted()
            val labels = choices.map { retentionLabel(it) }.toTypedArray()
            val cur = choices.indexOf(p.logRetentionDays()).coerceAtLeast(0)
            showChoice(R.string.log_retention, labels, cur) { which ->
                p.setLogRetentionDays(choices[which])
                retentionValue.text = retentionLabel(p.logRetentionDays())
            }
        }

        // language picker (bilingual EN/ID, follows system by default)
        val langValue: TextView = v.findViewById(R.id.language_value)
        fun langLabel(): String = when (p.appLanguage()) {
            "en" -> getString(R.string.language_english)
            "in" -> getString(R.string.language_indonesian)
            else -> getString(R.string.language_system)
        }
        langValue.text = langLabel()
        v.findViewById<View>(R.id.set_language).setOnClickListener {
            val codes = arrayOf("", "en", "in")
            val labels = arrayOf(
                getString(R.string.language_system),
                getString(R.string.language_english),
                getString(R.string.language_indonesian))
            val cur = codes.indexOf(p.appLanguage()).coerceAtLeast(0)
            AlertDialog.Builder(act)
                .setTitle(R.string.language)
                .setSingleChoiceItems(labels, cur) { d, which ->
                    p.setAppLanguage(codes[which])
                    d.dismiss()
                    act.recreate()
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }

        val clear: Button = v.findViewById(R.id.btn_clear_logs)
        clear.setOnClickListener {
            // Warning dialog: clearing logs now also resets the statistics,
            // so the current Home totals are shown before confirming.
            val t = app.logBus().totalsAll()
            val numFmt = java.text.NumberFormat.getIntegerInstance()
            val msg = getString(
                R.string.clear_logs_message_fmt,
                numFmt.format(t[0]), numFmt.format(t[1]))
            val dlg = AlertDialog.Builder(act)
                .setTitle(R.string.clear_logs)
                .setMessage(msg)
                .setPositiveButton(R.string.clear_logs_action) { _, _ ->
                    app.logBus().clear()
                    updateLogSize()
                    Toast.makeText(act, R.string.logs_cleared, Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .create()
            dlg.setOnShowListener {
                dlg.getButton(AlertDialog.BUTTON_POSITIVE)
                    .setTextColor(0xFFF26D6D.toInt())
            }
            dlg.show()
        }

        val export: Button = v.findViewById(R.id.btn_export_logs)
        export.setOnClickListener { exportLogs() }

        logSizeTv = v.findViewById(R.id.log_size_label)
        updateLogSize()

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

        // ---- updates (GitHub Releases) ----
        bind(v, R.id.sw_update_auto, p.updateAutoCheck(), p::setUpdateAutoCheck)
        val curTv: TextView = v.findViewById(R.id.update_current)
        curTv.text = "v" + Updater(act).installedVersion()
        updateStatusTv = v.findViewById(R.id.update_status)
        refreshUpdateStatus()
        val checkBtn: Button = v.findViewById(R.id.btn_check_update)
        checkBtn.setOnClickListener {
            checkBtn.isEnabled = false
            checkBtn.setText(R.string.checking_short)
            p.setLastUpdateCheck(System.currentTimeMillis())
            UpdateChecker.fetch { list, raw ->
                val a2 = activity ?: return@fetch
                if (raw != null) p.setCachedReleasesJson(raw)
                checkBtn.isEnabled = true
                checkBtn.setText(R.string.check_update)
                val latest = list?.firstOrNull()
                if (latest == null) {
                    Toast.makeText(a2, R.string.update_check_failed,
                        Toast.LENGTH_SHORT).show()
                } else if (UpdateChecker.isNewer(latest.version,
                        Updater(a2).installedVersion())) {
                    p.setUpdateAvailable(latest.tag)
                    Updater(a2).showUpdateDialog(latest)
                } else {
                    p.setUpdateAvailable("")
                    Toast.makeText(a2, R.string.update_uptodate,
                        Toast.LENGTH_SHORT).show()
                }
                refreshUpdateStatus()
            }
        }
        v.findViewById<View>(R.id.set_changelog).setOnClickListener {
            if (activity is MainActivity) {
                (activity as MainActivity).openChangelog()
            }
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
            ver.text = getString(R.string.version_fmt, vn)
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
                val langBefore = app.prefs().appLanguage()
                val result = BackupManager.importJson(app,
                    buf.toString(StandardCharsets.UTF_8.name()))
                Toast.makeText(act, result, Toast.LENGTH_LONG).show()
                // imported upstream settings take effect right away:
                // restart the VPN once when it is running (same rule as the Upstream tab)
                if (!result.startsWith("Error:")) {
                    val ma = act as? MainActivity
                    if (ma != null && ma.isVpnRunning()) ma.restartVpn()
                    // M7 follow-up: an imported language applies live too —
                    // recreate like the language picker does
                    if (app.prefs().appLanguage() != langBefore) act.recreate()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(act, getString(R.string.import_failed_fmt, e.message),
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
            Toast.makeText(act, getString(R.string.export_failed_fmt, e.message),
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
            Toast.makeText(act, getString(R.string.saved_to_download_fmt, name), Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "application/json"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, getString(R.string.share_settings)))
        } catch (e: Exception) {
            Toast.makeText(act, getString(R.string.export_failed_fmt, e.message),
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
                    R.string.debug_started,
                    Toast.LENGTH_LONG).show()
                // U-N5: (re)arm the elapsed-time ticker — the chain
                // stops itself whenever no capture is running, so
                // without this a Start from Settings left the button
                // label frozen at "0:00" while the capture ran.
                debugTicker?.let {
                    debugHandler.removeCallbacks(it)
                    debugHandler.postDelayed(it, 1000)
                }
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
            btn.text = getString(R.string.stop_share_debug_fmt,
                secs / 60, secs % 60)
        } else {
            btn.setText(R.string.debug_capture)
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
            Toast.makeText(act, getString(R.string.saved_to_download_fmt, name), Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "application/json"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, getString(R.string.share_debug)))
        } catch (e: Exception) {
            Toast.makeText(act, getString(R.string.debug_export_failed_fmt, e.message),
                Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroyView() {
        debugTicker?.let { debugHandler.removeCallbacks(it) }
        super.onDestroyView()
    }

    /** Single-choice dialog used by the advanced value rows. */
    private fun showChoice(
        titleRes: Int,
        labels: Array<String>,
        current: Int,
        onPick: (Int) -> Unit
    ) {
        val act = activity ?: return
        AlertDialog.Builder(act)
            .setTitle(titleRes)
            .setSingleChoiceItems(labels, current) { d, which ->
                onPick(which)
                d.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
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
            Toast.makeText(act, R.string.no_logs_to_export, Toast.LENGTH_SHORT).show()
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
            Toast.makeText(act, getString(R.string.saved_to_download_fmt, name), Toast.LENGTH_LONG).show()
            val share = Intent(Intent.ACTION_SEND)
            share.type = "text/csv"
            share.putExtra(Intent.EXTRA_STREAM, uri)
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(share, getString(R.string.share_log)))
        } catch (e: Exception) {
            Toast.makeText(act, getString(R.string.export_failed_fmt, e.message),
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
