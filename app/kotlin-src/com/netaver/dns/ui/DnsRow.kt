package com.netaver.dns.ui

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
            val lat = if (e.blocked) cv.context.getString(R.string.local_latency) else "${e.latencyMs}ms"
            val ipPart = if (e.resolvedIp.isEmpty()) "" else " · ${e.resolvedIp}"
            meta.text = "${e.app} · ${e.qtype} · ${FMT.format(Date(e.time))} · $lat$ipPart"
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
