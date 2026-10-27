package com.netaver.dns.util

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.Looper
import android.util.LruCache
import android.view.View
import android.widget.ImageView
import android.widget.TextView

import java.util.concurrent.Executors

/**
 * Real app icons for the Apps tab + detail screen (vc111).
 *
 * Why this shape (and not a one-liner in the adapter):
 * - PackageManager icon reads hit another app's resources (disk I/O), so
 *   they must never run on the UI thread for every row, or the list janks.
 * - ListView recycles rows: a late load must never land on a row that has
 *   since been rebound to another app. The ImageView is tagged with the uid
 *   it is loading for, and a load that no longer matches is dropped.
 * - The cache is touched ONLY on the main thread (checked in getView,
 *   filled in the posted-back runnable), so it needs no synchronization.
 * - Any failure (no package for the uid, app gone, SecurityException)
 *   leaves the letter tile visible — the exact pre-vc111 appearance.
 * - The single background thread lives with the process; tasks hold views
 *   only until they run (milliseconds), and setting a drawable on a
 *   detached view is harmless, so no shutdown hook is needed.
 */
object AppIcons {
    private const val MAX_CACHED = 128
    private val cache = LruCache<Int, Drawable>(MAX_CACHED)
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    /** Show the real icon for uid, or leave the letter tile visible. Safe to
     *  call from getView on every bind (cache hits are synchronous). */
    @JvmStatic
    fun load(pm: PackageManager, uid: Int, imageView: ImageView, letterView: TextView) {
        // Tag first: a pending load from a previous bind of this recycled
        // view must not overwrite the icon for the new uid.
        imageView.tag = uid
        // Reset to the fallback state; the icon (if any) replaces it below.
        imageView.visibility = View.GONE
        letterView.visibility = View.VISIBLE
        if (uid < 0) return
        val cached = cache.get(uid)
        if (cached != null) {
            imageView.setImageDrawable(cached)
            imageView.visibility = View.VISIBLE
            letterView.visibility = View.GONE
            return
        }
        executor.execute {
            val icon: Drawable? = try {
                val pkgs = pm.getPackagesForUid(uid)
                val pkg = pkgs?.firstOrNull() ?: return@execute
                pm.getApplicationIcon(pkg)
            } catch (_: Exception) {
                null
            }
            if (icon == null) return@execute
            mainHandler.post {
                // Cache + set on the main thread only (no synchronization).
                cache.put(uid, icon)
                if (imageView.tag == uid) {
                    imageView.setImageDrawable(icon)
                    imageView.visibility = View.VISIBLE
                    letterView.visibility = View.GONE
                }
            }
        }
    }
}
