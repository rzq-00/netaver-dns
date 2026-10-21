package com.netaver.dns.util

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

import com.netaver.dns.DnsVpnService

/** Auto-start protection after reboot when enabled. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED != intent.action) return
        val prefs = Prefs(context)
        if (!prefs.startOnBoot()) return
        // If VPN was authorized before, prepare() returns null and we can start.
        if (VpnService.prepare(context) != null) return
        val svc = Intent(context, DnsVpnService::class.java)
        svc.action = DnsVpnService.ACTION_START
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(svc)
        } else {
            context.startService(svc)
        }
    }
}
