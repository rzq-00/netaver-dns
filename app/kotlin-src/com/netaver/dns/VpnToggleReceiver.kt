package com.netaver.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.netaver.dns.ui.MainActivity

/**
 * Notification-shade toggle for the VPN: "Matikan" stops the service,
 * "Nyalakan" starts it again — no need to open the app.
 */
class VpnToggleReceiver : BroadcastReceiver() {

    override fun onReceive(ctx: Context, intent: Intent) {
        when (intent.action) {
            DnsVpnService.ACTION_STOP_VPN -> {
                // Prefer the direct ACTION_STOP service intent — the same
                // path as the in-app power button, which provably works.
                // stopService() alone did not take the service down on the
                // user's device, so it stays only as a fallback.
                if (DnsVpnService.vpnActive) {
                    try {
                        val i = Intent(ctx, DnsVpnService::class.java)
                        i.action = DnsVpnService.ACTION_STOP
                        ctx.startService(i)
                    } catch (e: Exception) {
                        ctx.stopService(Intent(ctx, DnsVpnService::class.java))
                    }
                } else {
                    ctx.stopService(Intent(ctx, DnsVpnService::class.java))
                }
                showStartNotification(ctx)
            }
            DnsVpnService.ACTION_START_VPN -> {
                ctx.getSystemService(NotificationManager::class.java)
                    ?.cancel(DnsVpnService.NOTIF_ID_START)
                try {
                    val i = Intent(ctx, DnsVpnService::class.java)
                    if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i)
                    else ctx.startService(i)
                } catch (e: Exception) {
                    Log.d(TAG, "start failed, opening app", e)
                    val i = Intent(ctx, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    ctx.startActivity(i)
                }
            }
        }
    }

    companion object {
        private const val TAG = "VpnToggle"

        fun showStartNotification(ctx: Context) {
            try {
                val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
                if (Build.VERSION.SDK_INT >= 26) {
                    nm.createNotificationChannel(NotificationChannel(
                        DnsVpnService.CHANNEL_ID, "NetAver DNS",
                        NotificationManager.IMPORTANCE_LOW))
                }
                val startIntent = Intent(ctx, VpnToggleReceiver::class.java)
                    .setAction(DnsVpnService.ACTION_START_VPN)
                val startPi = PendingIntent.getBroadcast(
                    ctx, 2, startIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                val openIntent = Intent(ctx, MainActivity::class.java)
                val openPi = PendingIntent.getActivity(
                    ctx, 0, openIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                val nb = Notification.Builder(ctx, DnsVpnService.CHANNEL_ID)
                    .setContentTitle("NetAver DNS mati")
                    .setContentText("Tap Nyalakan untuk menghidupkan lagi")
                    .setSmallIcon(R.mipmap.ic_launcher)
                    .setContentIntent(openPi)
                    .setAutoCancel(true)
                    .addAction(Notification.Action.Builder(
                        android.R.drawable.ic_media_play, "Nyalakan", startPi).build())
                if (Build.VERSION.SDK_INT >= 26)
                    nb.setChannelId(DnsVpnService.CHANNEL_ID)
                nm.notify(DnsVpnService.NOTIF_ID_START, nb.build())
            } catch (e: Exception) {
                Log.d(TAG, "show start notif failed", e)
            }
        }

        fun cancelStartNotification(ctx: Context) {
            try {
                ctx.getSystemService(NotificationManager::class.java)
                    ?.cancel(DnsVpnService.NOTIF_ID_START)
            } catch (_: Exception) { }
        }
    }
}
