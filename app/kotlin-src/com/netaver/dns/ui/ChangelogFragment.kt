package com.netaver.dns.ui

import android.app.Fragment
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView

import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.UpdateChecker
import com.netaver.dns.util.Updater

/** Changelog screen: release history from GitHub Releases (cached for offline). */
class ChangelogFragment : Fragment() {
    private var listBox: LinearLayout? = null
    private var emptyTv: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_changelog, container, false)
        val act = activity ?: return v
        listBox = v.findViewById(R.id.changelog_list)
        emptyTv = v.findViewById(R.id.changelog_empty)
        v.findViewById<View>(R.id.changelog_back).setOnClickListener {
            act.onBackPressed()
        }
        val app = act.application as NetAverApp
        val cache = app.prefs().cachedReleasesJson()
        if (cache.isNotEmpty()) {
            render(UpdateChecker.parse(cache))
        } else {
            emptyTv?.visibility = View.VISIBLE
        }
        UpdateChecker.fetch { list, raw ->
            val a = activity ?: return@fetch
            if (raw != null) {
                (a.application as NetAverApp).prefs().setCachedReleasesJson(raw)
            }
            if (list != null) render(list)
        }
        return v
    }

    private fun render(list: List<UpdateChecker.ReleaseInfo>) {
        val act = activity ?: return
        val box = listBox ?: return
        box.removeAllViews()
        emptyTv?.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        val installed = Updater(act).installedVersion()
        val d = act.resources.displayMetrics.density
        val latestTag = list.firstOrNull()?.tag ?: ""
        for (info in list) {
            val card = LinearLayout(act)
            card.orientation = LinearLayout.VERTICAL
            card.setBackgroundResource(R.drawable.card_bg)
            val cp = (14 * d).toInt()
            card.setPadding(cp, cp, cp, cp)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.bottomMargin = (8 * d).toInt()
            card.layoutParams = lp

            val head = LinearLayout(act)
            head.orientation = LinearLayout.HORIZONTAL
            head.gravity = Gravity.CENTER_VERTICAL
            val ver = TextView(act)
            ver.text = info.tag
            ver.setTextColor(0xFFE8EAF0.toInt())
            ver.textSize = 15f
            ver.setTypeface(ver.typeface, android.graphics.Typeface.BOLD)
            ver.layoutParams = LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            head.addView(ver)
            val isInstalled = info.version == installed
            val isNew = info.tag == latestTag &&
                UpdateChecker.isNewer(info.version, installed)
            if (isNew || isInstalled) {
                val badge = TextView(act)
                badge.setText(if (isNew) R.string.badge_new else R.string.badge_installed)
                badge.textSize = 10f
                badge.setTypeface(badge.typeface, android.graphics.Typeface.BOLD)
                if (isNew) {
                    badge.setBackgroundColor(0xFF2563EB.toInt())
                    badge.setTextColor(0xFFFFFFFF.toInt())
                } else {
                    badge.setBackgroundColor(0xFF12331F.toInt())
                    badge.setTextColor(0xFF4ADE80.toInt())
                }
                val bp = (4 * d).toInt()
                badge.setPadding((8 * d).toInt(), bp, (8 * d).toInt(), bp)
                head.addView(badge)
            }
            card.addView(head)

            val date = TextView(act)
            date.text = UpdateChecker.displayDate(info.publishedAt)
            date.setTextColor(0xFF8B93A7.toInt())
            date.textSize = 12f
            date.setPadding(0, (2 * d).toInt(), 0, (8 * d).toInt())
            card.addView(date)

            val notes = TextView(act)
            notes.text = UpdateChecker.plainNotes(info.notes)
            notes.setTextColor(0xFFC6CCDA.toInt())
            notes.textSize = 13f
            card.addView(notes)

            box.addView(card)
        }
    }
}
