package com.netaver.dns

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.netaver.dns.ui.MainActivity

/**
 * Quick Settings tile: one tap in the notification shade toggles the VPN,
 * reusing the same start/stop broadcasts as the notification buttons.
 * Add it once via the shade's edit (pencil) panel.
 */
class VpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        when {
            DnsVpnService.vpnActive -> {
                // Stop the same way the in-app power button does: a direct
                // ACTION_STOP intent to the service. The old route (broadcast
                // to VpnToggleReceiver -> stopService) did not take the
                // service down on the user's device — the tile could turn
                // the VPN on but never off.
                val i = Intent(this, DnsVpnService::class.java)
                i.action = DnsVpnService.ACTION_STOP
                startService(i)
            }
            VpnService.prepare(this) == null -> {
                sendBroadcast(Intent(this, VpnToggleReceiver::class.java)
                    .setAction(DnsVpnService.ACTION_START_VPN))
            }
            else -> {
                // VPN consent not granted yet — only the app can ask for it.
                val i = Intent(this, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                @Suppress("DEPRECATION")
                startActivityAndCollapse(i)
                return
            }
        }
        // The service flips vpnActive asynchronously; repaint shortly after,
        // and DnsVpnService also calls requestRefresh() on state changes.
        Handler(Looper.getMainLooper()).postDelayed({ refresh() }, 700)
    }

    private fun refresh() {
        val t = qsTile ?: return
        val on = DnsVpnService.vpnActive
        t.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        t.label = "NetAver DNS"
        if (Build.VERSION.SDK_INT >= 29) {
            val w = com.netaver.dns.util.Lang.wrap(this)
            t.subtitle = w.getString(if (on) R.string.tile_active else R.string.tile_inactive)
        }
        t.icon = Icon.createWithResource(this, R.drawable.ic_power)
        t.updateTile()
    }

    companion object {
        /** Ask the system to re-run onStartListening so the tile repaints. Safe no-op when the tile was never added. */
        fun requestRefresh(ctx: Context) {
            try {
                requestListeningState(ctx, ComponentName(ctx, VpnTileService::class.java))
            } catch (_: Exception) { }
        }
    }
}
