package com.netaver.dns.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.log.Entries
import com.netaver.dns.net.GeoIp

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** AdGuard Home-style query detail dialog, shared by DNS log and app detail. */
class DnsDetailDialog private constructor() {
    companion object {
        @JvmStatic
        fun show(activity: Activity, e: Entries.DnsEntry) {
            val app = activity.application as NetAverApp
            val flag = GeoIp.flagFor(e.countryCode)
            val sb = StringBuilder()
            sb.append(activity.getString(R.string.detail_domain)).append(": ").append(e.domain).append("\n")
            sb.append(activity.getString(R.string.detail_type)).append(": ").append(e.qtype).append("\n")
            sb.append(activity.getString(R.string.detail_time)).append(": ").append(SimpleDateFormat("HH:mm:ss", Locale.US)
                .format(Date(e.time))).append("\n")
            sb.append(activity.getString(R.string.detail_app)).append(": ").append(e.app).append("\n")
            sb.append(activity.getString(R.string.detail_status)).append(": ").append(activity.getString(if (e.blocked) R.string.blocked else R.string.allowed)).append("\n")
            if (e.matchInfo.isNotEmpty()) {
                val mi = when (e.matchInfo) {
                    "Custom rule" -> activity.getString(R.string.match_custom_rule)
                    "Allowlist rule" -> activity.getString(R.string.match_allowlist_rule)
                    "Bypass blocked (port 853)" -> activity.getString(R.string.match_bypass_blocked)
                    else -> e.matchInfo
                }
                sb.append(activity.getString(R.string.detail_matched)).append(": ").append(mi).append("\n")
            }
            if (e.resolvedIp.isNotEmpty()) {
                sb.append(activity.getString(R.string.detail_answer)).append(": ").append(e.resolvedIp)
                if (flag.isNotEmpty()) sb.append(" ").append(flag)
                if (e.countryCode.isNotEmpty()) sb.append(" (").append(e.countryCode).append(")")
                sb.append("\n")
            }
            sb.append(activity.getString(R.string.detail_latency)).append(": ").append(if (e.blocked) activity.getString(R.string.local_latency) else "${e.latencyMs}ms").append("\n")
            sb.append(activity.getString(R.string.detail_upstream)).append(": ").append(app.prefs().upstreamLabel(activity))

            val tv = TextView(activity)
            tv.text = sb.toString()
            tv.setTextColor(0xFFF1F5F9.toInt())
            tv.textSize = 14f
            val pad = (16 * activity.resources.displayMetrics.density).toInt()
            tv.setPadding(pad, pad, pad, pad)

            val b = AlertDialog.Builder(activity)
                .setTitle((if (e.blocked) "⛔ " else "✅ ") + e.domain)
                .setView(tv)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton(R.string.copy_label) { _, _ ->
                    val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    cm?.setPrimaryClip(ClipData.newPlainText("domain", e.domain))
                    Toast.makeText(activity, R.string.copied, Toast.LENGTH_SHORT).show()
                }
            if (e.blocked) {
                b.setNegativeButton(R.string.allow_domain) { _, _ ->
                    app.addCustomRule("@@||" + e.domain + "^")
                    Toast.makeText(activity, activity.getString(R.string.domain_allowed_fmt, e.domain), Toast.LENGTH_SHORT).show()
                }
            } else {
                b.setNegativeButton(R.string.block_domain) { _, _ ->
                    app.addCustomRule("||" + e.domain + "^")
                    Toast.makeText(activity, activity.getString(R.string.domain_blocked_fmt, e.domain), Toast.LENGTH_SHORT).show()
                }
            }
            b.show()
        }
    }
}
