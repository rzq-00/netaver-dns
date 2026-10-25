package com.netaver.dns.ui

import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView

import com.netaver.dns.R
import com.netaver.dns.log.Entries
import com.netaver.dns.net.GeoIp

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Shared DNS log row binding (DNS log tab + app detail page). */
class DnsRow private constructor() {
    companion object {
        private val FMT = SimpleDateFormat("HH:mm:ss", Locale.US)

        @JvmStatic
        fun inflate(parent: ViewGroup): View {
            return LayoutInflater.from(parent.context).inflate(R.layout.item_dns, parent, false)
        }

        @JvmStatic
        fun bind(cv: View, e: Entries.DnsEntry) {
            val domain: TextView = cv.findViewById(R.id.item_domain)
            val meta: TextView = cv.findViewById(R.id.item_meta)
            val badge: TextView = cv.findViewById(R.id.item_badge)
            val flag = GeoIp.flagFor(e.countryCode)
            domain.text = (if (flag.isEmpty()) "" else "$flag ") + e.domain
            val ipPart = if (e.resolvedIp.isEmpty()) "" else " · ${e.resolvedIp}"
            if (!e.blocked && e.fromCache) {
                // cache-served: the word "Cache" in accent blue instead of a ms value
                val sb = SpannableStringBuilder()
                sb.append("${e.app} · ${e.qtype} · ${FMT.format(Date(e.time))} · ")
                val start = sb.length
                sb.append(cv.context.getString(R.string.filter_cache))
                sb.setSpan(ForegroundColorSpan(0xFF5B9BFF.toInt()), start, sb.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(StyleSpan(android.graphics.Typeface.BOLD), start, sb.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.append(ipPart)
                meta.text = sb
            } else {
                val lat = if (e.blocked) cv.context.getString(R.string.local_latency) else "${e.latencyMs}ms"
                meta.text = "${e.app} · ${e.qtype} · ${FMT.format(Date(e.time))} · $lat$ipPart"
            }
            badge.text = cv.context.getString(if (e.isBypass) R.string.bypass_badge else if (e.blocked) R.string.blocked else R.string.allowed)
            badge.setTextColor(
                (if (e.isBypass) 0xFFFBBF24 else if (e.blocked) 0xFFF87171 else 0xFF4ADE80).toInt()
            )
            badge.setBackgroundColor(
                (if (e.isBypass) 0xFF3A2A10 else if (e.blocked) 0xFF3A1420 else 0xFF12331F).toInt()
            )
        }
    }
}
