package com.netaver.dns.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.NetAverApp
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
            sb.append("Domain: ").append(e.domain).append("\n")
            sb.append("Type: ").append(e.qtype).append("\n")
            sb.append("Time: ").append(SimpleDateFormat("HH:mm:ss", Locale.US)
                .format(Date(e.time))).append("\n")
            sb.append("App: ").append(e.app).append("\n")
            sb.append("Status: ").append(if (e.blocked) "BLOCKED" else "ALLOWED").append("\n")
            if (e.matchInfo.isNotEmpty()) sb.append("Matched: ").append(e.matchInfo).append("\n")
            if (e.resolvedIp.isNotEmpty()) {
                sb.append("Answer: ").append(e.resolvedIp)
                if (flag.isNotEmpty()) sb.append(" ").append(flag)
                if (e.countryCode.isNotEmpty()) sb.append(" (").append(e.countryCode).append(")")
                sb.append("\n")
            }
            sb.append("Latency: ").append(if (e.blocked) "local" else "${e.latencyMs}ms").append("\n")
            sb.append("Upstream: ").append(app.prefs().upstreamLabel())

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
                .setNeutralButton("📋 Copy") { _, _ ->
                    val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    cm?.setPrimaryClip(ClipData.newPlainText("domain", e.domain))
                    Toast.makeText(activity, "Copied", Toast.LENGTH_SHORT).show()
                }
            if (e.blocked) {
                b.setNegativeButton("Allow domain") { _, _ ->
                    app.addCustomRule("@@||" + e.domain + "^")
                    Toast.makeText(activity, e.domain + " allowed", Toast.LENGTH_SHORT).show()
                }
            } else {
                b.setNegativeButton("⛔ Block domain") { _, _ ->
                    app.addCustomRule("||" + e.domain + "^")
                    Toast.makeText(activity, e.domain + " blocked", Toast.LENGTH_SHORT).show()
                }
            }
            b.show()
        }
    }
}
