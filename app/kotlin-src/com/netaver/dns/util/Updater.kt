package com.netaver.dns.util

import android.app.Activity
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.netaver.dns.R
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Update UI + manual-install flow: dialog with release notes, download
 * with progress, signing-certificate verification against the running
 * app, then the verified APK is saved to Downloads and the user opens
 * it from there to install. Deliberately NO REQUEST_INSTALL_PACKAGES:
 * Play Protect flags sideloaded apps holding that permission as
 * harmful. The APK only ever comes from the official GitHub release
 * asset URL (HTTPS).
 */
class Updater(private val act: Activity) {
    private val handler = Handler(Looper.getMainLooper())

    @Volatile
    private var cancelled = false

    fun installedVersion(): String = try {
        act.packageManager.getPackageInfo(act.packageName, 0).versionName ?: "0"
    } catch (e: Exception) {
        "0"
    }

    fun showUpdateDialog(info: UpdateChecker.ReleaseInfo) {
        val pad = (20 * act.resources.displayMetrics.density).toInt()
        val box = LinearLayout(act)
        box.orientation = LinearLayout.VERTICAL
        box.setPadding(pad, pad / 2, pad, 0)
        val meta = TextView(act)
        meta.text = act.getString(R.string.app_name) + " " + info.tag + " · " +
            UpdateChecker.fmtSize(info.apkSize) + " · " +
            UpdateChecker.displayDate(info.publishedAt)
        meta.setTextColor(0xFF8B93A7.toInt())
        meta.textSize = 13f
        box.addView(meta)
        val notes = TextView(act)
        notes.text = UpdateChecker.plainNotes(info.notes)
        notes.setTextColor(0xFFC6CCDA.toInt())
        notes.textSize = 13f
        notes.setPadding(0, pad / 2, 0, 0)
        box.addView(notes)
        val note = TextView(act)
        note.setText(R.string.update_verify_note)
        note.setTextColor(0xFF5B6478.toInt())
        note.textSize = 11f
        note.setPadding(0, pad / 2, 0, pad)
        box.addView(note)
        val sv = ScrollView(act)
        sv.addView(box)
        AlertDialog.Builder(act)
            .setTitle(R.string.update_available_title)
            .setView(sv)
            .setNegativeButton(R.string.later, null)
            .setPositiveButton(R.string.update_now) { _, _ -> download(info) }
            .show()
    }

    private fun download(info: UpdateChecker.ReleaseInfo) {
        cancelled = false
        val pad = (20 * act.resources.displayMetrics.density).toInt()
        val box = LinearLayout(act)
        box.orientation = LinearLayout.VERTICAL
        box.setPadding(pad, pad, pad, pad / 2)
        val bar = ProgressBar(act, null, android.R.attr.progressBarStyleHorizontal)
        bar.max = 100
        bar.progress = 0
        box.addView(bar)
        val status = TextView(act)
        status.setTextColor(0xFF8B93A7.toInt())
        status.textSize = 13f
        status.setPadding(0, pad / 2, 0, 0)
        status.text = act.getString(R.string.update_progress_fmt, 0,
            UpdateChecker.fmtSize(0), UpdateChecker.fmtSize(info.apkSize))
        box.addView(status)
        val dlg = AlertDialog.Builder(act)
            .setTitle(R.string.update_downloading)
            .setView(box)
            .setCancelable(false)
            .setNegativeButton(R.string.cancel) { _, _ -> cancelled = true }
            .show()
        val dest = File(act.cacheDir, "update.apk")
        Thread({
            var ok = false
            try {
                val c = URL(info.apkUrl).openConnection() as HttpURLConnection
                c.connectTimeout = 15000
                c.readTimeout = 30000
                c.setRequestProperty("User-Agent", "NetAver-DNS")
                val total = if (info.apkSize > 0) info.apkSize
                    else c.contentLength.toLong()
                var done = 0L
                c.inputStream.use { ins ->
                    FileOutputStream(dest).use { out ->
                        val tmp = ByteArray(32 * 1024)
                        var n: Int
                        while (ins.read(tmp).also { n = it } > 0) {
                            if (cancelled) break
                            out.write(tmp, 0, n)
                            done += n
                            val pct = if (total > 0) (done * 100 / total).toInt() else 0
                            val d = done
                            handler.post {
                                if (dlg.isShowing) {
                                    bar.progress = pct
                                    status.text = act.getString(
                                        R.string.update_progress_fmt, pct,
                                        UpdateChecker.fmtSize(d),
                                        UpdateChecker.fmtSize(total))
                                }
                            }
                        }
                    }
                }
                c.disconnect()
                ok = !cancelled && dest.exists() && dest.length() > 0 &&
                    (info.apkSize <= 0 || dest.length() == info.apkSize)
            } catch (e: Exception) {
                ok = false
            }
            val success = ok
            handler.post {
                if (cancelled) {
                    dest.delete()
                    dlg.dismiss()
                    return@post
                }
                if (!success) {
                    dest.delete()
                    dlg.dismiss()
                    Toast.makeText(act, R.string.update_download_failed,
                        Toast.LENGTH_LONG).show()
                    return@post
                }
                status.setText(R.string.update_verifying)
                Thread({
                    val good = verifySignature(dest) && saveToDownloads(dest, info)
                    handler.post {
                        dlg.dismiss()
                        dest.delete()
                        if (good) {
                            // A2 fix: the activity may be finished/destroyed
                            // (e.g. rotated) by now; showing the ready dialog
                            // would throw BadToken. The verified APK is
                            // already in Downloads — only the dialog is skipped.
                            if (!act.isFinishing && !act.isDestroyed) {
                                showReadyDialog(info)
                            }
                        } else {
                            Toast.makeText(act, R.string.update_sig_bad,
                                Toast.LENGTH_LONG).show()
                        }
                    }
                }, "update-verify").start()
            }
        }, "update-download").start()
    }

    /** The downloaded APK must be signed with the very same certificate. */
    private fun verifySignature(apk: File): Boolean {
        return try {
            val pm = act.packageManager
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            val own = pm.getPackageInfo(act.packageName, flags)
                .signingInfo?.apkContentsSigners
            val arc = pm.getPackageArchiveInfo(apk.path, flags)
                ?.signingInfo?.apkContentsSigners
            if (own.isNullOrEmpty() || arc.isNullOrEmpty()) false
            else own[0].toByteArray().contentEquals(arc[0].toByteArray())
        } catch (e: Exception) {
            false
        }
    }

    /** Copy the verified APK into Downloads (MediaStore, no permission needed). */
    private fun saveToDownloads(apk: File, info: UpdateChecker.ReleaseInfo): Boolean {
        return try {
            val name = "NetAverDNS-" + info.tag + ".apk"
            val cv = ContentValues()
            cv.put(MediaStore.Downloads.DISPLAY_NAME, name)
            cv.put(MediaStore.Downloads.MIME_TYPE,
                "application/vnd.android.package-archive")
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            val uri = act.contentResolver.insert(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: return false
            act.contentResolver.openOutputStream(uri).use { out ->
                if (out == null) return false
                apk.inputStream().use { ins -> ins.copyTo(out) }
            }
            true
        } catch (e: Exception) {
            false
        }
    }

    /** Final step is manual by design: the user opens the APK from Downloads. */
    private fun showReadyDialog(info: UpdateChecker.ReleaseInfo) {
        AlertDialog.Builder(act)
            .setTitle(R.string.update_ready_title)
            .setMessage(act.getString(R.string.update_ready_msg, info.tag))
            .setNegativeButton(R.string.later, null)
            .setPositiveButton(R.string.update_open_downloads) { _, _ ->
                try {
                    act.startActivity(Intent("android.intent.action.VIEW_DOWNLOADS")
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (e: Exception) {
                }
            }
            .show()
    }
}
