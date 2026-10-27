package com.netaver.dns.ui

import android.app.AlertDialog
import android.app.Fragment
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast

import com.netaver.dns.DnsVpnService
import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs
import com.netaver.dns.util.ProviderCatalog

/**
 * Upstream tab: mode + protocol selectors, the ACTIVE upstream list shown by
 * provider name (resolved via ProviderCatalog), and a catalog of well-known
 * providers to add from. Replaces the old upstream card on Home.
 */
class UpstreamFragment : Fragment() {
    private lateinit var root: LinearLayout
    private val pingViews = HashMap<String, TextView>()
    private val handler = Handler(Looper.getMainLooper())
    private var ticker: Runnable? = null
    private var building = false

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val v = inflater.inflate(R.layout.fragment_upstream, container, false)
        root = v.findViewById(R.id.up_root)
        (activity!!.application as NetAverApp).prefs().migrateUpstreamsIfNeeded()
        rebuild()
        ticker = Runnable {
            refreshStatus()
            handler.postDelayed(ticker!!, 2000)
        }
        return v
    }

    override fun onResume() {
        super.onResume()
        rebuild()
        ticker?.let { handler.post(it) }
    }

    override fun onPause() {
        super.onPause()
        ticker?.let { handler.removeCallbacks(it) }
    }

    private fun prefs(): Prefs = (activity!!.application as NetAverApp).prefs()

    /** After an upstream-config change: restart the VPN (off→on) so it takes
     *  effect when the VPN is running; a no-op while the VPN is off. */
    private fun applyChange() {
        val a = activity as? MainActivity ?: return
        if (a.isVpnRunning()) a.restartVpn()
    }

    // ---------- building blocks ----------

    private fun card(): LinearLayout {
        val c = LinearLayout(activity)
        c.orientation = LinearLayout.VERTICAL
        c.setBackgroundResource(R.drawable.card_bg)
        c.setPadding(dp(12), dp(12), dp(12), dp(12))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.bottomMargin = dp(12)
        c.layoutParams = lp
        return c
    }

    private fun sectionLabel(text: String) {
        val t = TextView(activity)
        t.text = text
        t.setTextColor(0xFF8B93A7.toInt())
        t.textSize = 11f
        t.setPadding(0, dp(2), 0, dp(6))
        root.addView(t)
    }

    private fun cardLabel(text: String): TextView {
        val t = TextView(activity)
        t.text = text
        t.setTextColor(0xFF8B93A7.toInt())
        t.textSize = 11f
        t.setPadding(0, 0, 0, dp(6))
        return t
    }

    private fun chip(text: String, accent: Boolean): TextView {
        val t = TextView(activity)
        t.text = text
        t.textSize = 10.5f
        t.setTextColor((if (accent) 0xFF60A5FA else 0xFFA9B4C8).toInt())
        t.setBackgroundResource(R.drawable.badge_bg)
        t.setPadding(dp(7), dp(2), dp(7), dp(2))
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.marginEnd = dp(6)
        t.layoutParams = lp
        return t
    }

    private fun radio(text: String, checked: Boolean): RadioButton {
        val r = RadioButton(activity)
        r.id = View.generateViewId()
        r.text = text
        r.isChecked = checked
        r.setTextColor(0xFFE8EAF0.toInt())
        r.textSize = 14f
        return r
    }

    // ---------- whole-tab rebuild ----------

    private fun rebuild() {
        val act = activity ?: return
        if (!::root.isInitialized) return
        building = true
        pingViews.clear()
        root.removeAllViews()
        val p = prefs()

        // MODE card
        val modeCard = card()
        modeCard.addView(cardLabel(getString(R.string.mode_label)))
        val modeGroup = RadioGroup(act)
        modeGroup.orientation = RadioGroup.HORIZONTAL
        val rPar = radio(getString(R.string.mode_parallel), p.upstreamMode() == Prefs.MODE_PARALLEL)
        val rFast = radio(getString(R.string.mode_fastest), p.upstreamMode() == Prefs.MODE_FASTEST)
        val rSeq = radio(getString(R.string.mode_sequential), p.upstreamMode() == Prefs.MODE_SEQUENTIAL)
        modeGroup.addView(rPar); modeGroup.addView(rFast); modeGroup.addView(rSeq)
        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (building) return@setOnCheckedChangeListener
            val m = when (checkedId) {
                rFast.id -> Prefs.MODE_FASTEST
                rSeq.id -> Prefs.MODE_SEQUENTIAL
                else -> Prefs.MODE_PARALLEL
            }
            prefs().setUpstreamMode(m)
            applyChange()
        }
        modeCard.addView(modeGroup)
        val modeDesc = TextView(act)
        modeDesc.text = getString(R.string.mode_desc)
        modeDesc.setTextColor(0xFF6E7794.toInt())
        modeDesc.textSize = 11f
        modeDesc.setPadding(0, dp(4), 0, 0)
        modeCard.addView(modeDesc)
        root.addView(modeCard)

        // ACTIVE card
        val specs = p.upstreamList()
        val actCard = card()
        val modeName = when (p.upstreamMode()) {
            Prefs.MODE_FASTEST -> getString(R.string.mode_fastest)
            Prefs.MODE_SEQUENTIAL -> getString(R.string.mode_sequential)
            else -> getString(R.string.mode_parallel)
        }
        actCard.addView(cardLabel("$modeName - ${specs.size} up to ${Prefs.MAX_UPSTREAMS} Upstream"))
        if (specs.isEmpty()) {
            val t = TextView(act)
            t.setText(R.string.empty_upstreams)
            t.setTextColor(0xFF8B93A7.toInt())
            t.textSize = 13f
            actCard.addView(t)
        }
        specs.forEachIndexed { idx, spec ->
            actCard.addView(activeRow(idx, spec, specs.size))
        }
        root.addView(actCard)

        refreshStatus()

        // Catalog
        sectionLabel(getString(R.string.up_add_provider))
        val inList = HashSet<String>()
        for (s in specs) {
            val id = ProviderCatalog.identify(s, p.getProtocol())
            if (id.known) inList.add(id.providerName)
        }
        // Saved customs (history) always sit ON TOP: above the 8 built-in
        // providers and above the Custom input card. Customs already active
        // today must survive being removed tomorrow, so seed them on first
        // sight (idempotent: rememberCustom dedupes). Rendered only when NOT
        // active: an active custom already shows in the active card above,
        // and removing it from active makes it reappear here for one-tap
        // re-adding. Tapping a history card opens the edit dialog.
        for (s in specs) {
            val id = ProviderCatalog.identify(s, p.getProtocol())
            if (!id.known) rememberCustom(s)
        }
        val activeKeys = specs.map { ProviderCatalog.endpointKey(it, p) }.toSet()
        for (h in prefs().customUpstreamHistory()) {
            if (specs.contains(h)) continue
            if (activeKeys.contains(ProviderCatalog.endpointKey(h, p))) continue
            root.addView(historyCard(h))
        }
        for ((i, provider) in ProviderCatalog.providers.withIndex()) {
            root.addView(providerCard(i, provider, inList.contains(provider.name)))
        }
        root.addView(customCard())
        building = false
    }

    private fun activeRow(idx: Int, spec: String, count: Int): View {
        val act = activity!!
        val p = prefs()
        val id = ProviderCatalog.identify(spec, p.getProtocol())
        val row = LinearLayout(act)
        row.orientation = LinearLayout.HORIZONTAL
        row.setPadding(0, dp(7), 0, dp(7))

        val num = TextView(act)
        num.text = "${idx + 1}"
        num.setTextColor(0xFF8B93A7.toInt())
        num.textSize = 13f
        num.setPadding(0, dp(2), dp(10), 0)
        row.addView(num)

        val mid = LinearLayout(act)
        mid.orientation = LinearLayout.VERTICAL
        mid.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val nameRow = LinearLayout(act)
        nameRow.orientation = LinearLayout.HORIZONTAL
        val name = TextView(act)
        name.text = if (id.known) id.providerName
            else (p.customUpstreamName(spec) ?: getString(R.string.up_custom_name))
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 15f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        nameRow.addView(name)
        val ch = chip(ProviderCatalog.chipText(id), true)
        val chLp = ch.layoutParams as LinearLayout.LayoutParams
        chLp.marginStart = dp(8)
        ch.layoutParams = chLp
        nameRow.addView(ch)
        mid.addView(nameRow)
        val addr = TextView(act)
        addr.text = ProviderCatalog.addressLine(spec)
        addr.setTextColor(0xFF8B93A7.toInt())
        addr.textSize = 11.5f
        addr.typeface = android.graphics.Typeface.MONOSPACE
        mid.addView(addr)
        row.addView(mid)

        // per-provider ping (passive latency EMA published by the service)
        val pingCol = LinearLayout(act)
        pingCol.orientation = LinearLayout.VERTICAL
        pingCol.gravity = android.view.Gravity.END
        pingCol.setPadding(dp(10), dp(2), dp(12), 0)
        val pl = TextView(act)
        pl.setText(R.string.ping_label)
        pl.setTextColor(0xFF6E7794.toInt())
        pl.textSize = 9.5f
        pl.gravity = android.view.Gravity.END
        pingCol.addView(pl)
        val pv = TextView(act)
        pv.text = "—"
        pv.setTextColor(0xFF6E7794.toInt())
        pv.textSize = 13f
        pv.setTypeface(pv.typeface, android.graphics.Typeface.BOLD)
        pv.gravity = android.view.Gravity.END
        pingCol.addView(pv)
        pingViews[spec] = pv
        row.addView(pingCol)

        val del = Button(act)
        del.text = "✕"
        del.setOnClickListener {
            val specs = prefs().upstreamList().toMutableList()
            if (specs.size <= 1) {
                Toast.makeText(act, R.string.min_one_upstream, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (idx in specs.indices) {
                specs.removeAt(idx)
                prefs().setUpstreamList(specs)
                rebuild()
                applyChange()
            }
        }
        row.addView(del)
        if (idx < count - 1) {
            // separators handled by row padding; keep rows visually light
        }
        return row
    }

    private fun providerCard(index: Int, provider: ProviderCatalog.Provider, isInList: Boolean): View {
        val act = activity!!
        val c = card()
        val top = LinearLayout(act)
        top.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(act)
        left.orientation = LinearLayout.VERTICAL
        left.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val name = TextView(act)
        name.text = provider.name
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 16f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        left.addView(name)
        val trait = TextView(act)
        trait.setText(provider.traitRes)
        trait.setTextColor(0xFF8B93A7.toInt())
        trait.textSize = 12.5f
        left.addView(trait)
        top.addView(left)
        if (isInList) {
            val t = TextView(act)
            t.text = getString(R.string.up_in_list)
            t.setTextColor(0xFF8B93A7.toInt())
            t.textSize = 12f
            t.setTypeface(t.typeface, android.graphics.Typeface.BOLD)
            top.addView(t)
        } else {
            val b = Button(act)
            b.setText(R.string.add)
            b.setOnClickListener { (act as MainActivity).openProviderDetail(index) }
            top.addView(b)
        }
        c.addView(top)
        val names = provider.variants.map { it.name }.filter { it.isNotEmpty() }
        if (names.isNotEmpty()) {
            val chips = LinearLayout(act)
            chips.orientation = LinearLayout.HORIZONTAL
            chips.setPadding(0, dp(8), 0, 0)
            for (n in names) chips.addView(chip(n, false))
            c.addView(chips)
        }
        c.setOnClickListener { (act as MainActivity).openProviderDetail(index) }
        return c
    }

    private fun customCard(): View {
        val act = activity!!
        val c = card()
        val top = LinearLayout(act)
        top.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(act)
        left.orientation = LinearLayout.VERTICAL
        left.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val name = TextView(act)
        name.setText(R.string.custom_ellipsis)
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 16f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        left.addView(name)
        val trait = TextView(act)
        trait.setText(R.string.trait_custom)
        trait.setTextColor(0xFF8B93A7.toInt())
        trait.textSize = 12.5f
        left.addView(trait)
        top.addView(left)
        c.addView(top)
        // No ADD button: tapping the card itself opens the name+address dialog.
        c.setOnClickListener { showCustomDialog() }
        return c
    }

    /** Remember a custom upstream in history (dedupe: exact + same endpoint).
     *  Only explicit DoT/DoH customs are remembered (same rule as the dialog).
     *  History is independent of the active list: removing from active does
     *  NOT remove from history. No rebuild here (callers rebuild). */
    private fun rememberCustom(spec: String) {
        val raw = spec.trim()
        if (raw.isEmpty()) return
        val low = raw.lowercase()
        if (!low.startsWith("tls://") && !low.startsWith("https://")) return
        val p = prefs()
        val hist = p.customUpstreamHistory().toMutableList()
        if (hist.contains(raw)) return
        val key = ProviderCatalog.endpointKey(raw, p)
        if (hist.any { ProviderCatalog.endpointKey(it, p) == key }) return
        hist.add(raw)
        p.setCustomUpstreamHistory(hist)
    }

    /** Add a spec to the ACTIVE list (shared by the custom dialog and history
     *  cards). Returns true if added. Guards: max 5, exact + endpoint dupe
     *  (U5: a different spelling of an already-active server is a dupe too).
     *  Does NOT touch history (callers remember separately). */
    private fun addUpstreamSpec(spec: String): Boolean {
        val act = activity ?: return false
        val specs = prefs().upstreamList().toMutableList()
        if (specs.size >= Prefs.MAX_UPSTREAMS) {
            Toast.makeText(act, getString(R.string.max_upstreams_fmt, Prefs.MAX_UPSTREAMS),
                Toast.LENGTH_SHORT).show()
            return false
        }
        if (specs.contains(spec)) {
            Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
            return false
        }
        val newKey = ProviderCatalog.endpointKey(spec, prefs())
        if (specs.any { ProviderCatalog.endpointKey(it, prefs()) == newKey }) {
            Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
            return false
        }
        specs.add(spec)
        prefs().setUpstreamList(specs)
        rebuild()
        applyChange()
        return true
    }

    /** A saved custom upstream, shown above the providers: name (or
     *  "Custom" when unnamed) + address + DoT/DoH chip, Tambah (re-add to
     *  active, no retyping) and ✕ (forget from history only; never touches
     *  the active list or the stored name). Tapping the card itself opens
     *  the edit dialog (prefilled name + address). */
    private fun historyCard(spec: String): View {
        val act = activity!!
        val c = card()
        val top = LinearLayout(act)
        top.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(act)
        left.orientation = LinearLayout.VERTICAL
        left.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        val nameRow = LinearLayout(act)
        nameRow.orientation = LinearLayout.HORIZONTAL
        val name = TextView(act)
        name.text = prefs().customUpstreamName(spec) ?: getString(R.string.up_custom_name)
        name.setTextColor(0xFFE8EAF0.toInt())
        name.textSize = 16f
        name.setTypeface(name.typeface, android.graphics.Typeface.BOLD)
        nameRow.addView(name)
        val id = ProviderCatalog.identify(spec, prefs().getProtocol())
        val ch = chip(ProviderCatalog.chipText(id), true)
        val chLp = ch.layoutParams as LinearLayout.LayoutParams
        chLp.marginStart = dp(8)
        ch.layoutParams = chLp
        nameRow.addView(ch)
        left.addView(nameRow)
        val addr = TextView(act)
        addr.text = ProviderCatalog.addressLine(spec)
        addr.setTextColor(0xFF8B93A7.toInt())
        addr.textSize = 11.5f
        addr.typeface = android.graphics.Typeface.MONOSPACE
        left.addView(addr)
        top.addView(left)
        val b = Button(act)
        b.setText(R.string.add)
        b.setOnClickListener { addUpstreamSpec(spec) }
        top.addView(b)
        val del = Button(act)
        del.text = "✕"
        del.setOnClickListener {
            val p = prefs()
            val key = ProviderCatalog.endpointKey(spec, p)
            val hist = p.customUpstreamHistory().filter {
                it != spec && ProviderCatalog.endpointKey(it, p) != key
            }
            p.setCustomUpstreamHistory(hist)
            rebuild()
        }
        top.addView(del)
        c.addView(top)
        // Tapping the card (not the buttons) opens the edit dialog.
        c.setOnClickListener { showEditCustomDialog(spec) }
        return c
    }

    /** Edit a saved custom: the same name+address dialog as adding, prefilled
     *  with the current values. Saving updates the history entry in place
     *  (order kept) and moves/updates its name. The new address must not
     *  duplicate another history entry or an active upstream. History-only:
     *  never touches the active list, never restarts the VPN. */
    private fun showEditCustomDialog(oldSpec: String) {
        val act = activity ?: return
        val p = prefs()
        val layout = LinearLayout(act)
        layout.orientation = LinearLayout.VERTICAL
        val pad = dp(16)
        layout.setPadding(pad, dp(8), pad, 0)
        val nameEt = EditText(act)
        nameEt.hint = "Name (optional)"
        nameEt.setSingleLine(true)
        nameEt.setText(p.customUpstreamName(oldSpec) ?: "")
        val nameLp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        nameLp.bottomMargin = dp(8)
        nameEt.layoutParams = nameLp
        layout.addView(nameEt)
        val et = EditText(act)
        et.hint = "tls://dns.example.com or https://dns.example.com/dns-query"
        et.setSingleLine(true)
        et.setText(oldSpec)
        et.layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        layout.addView(et)
        AlertDialog.Builder(act)
            .setTitle(R.string.custom_ellipsis)
            .setView(layout)
            .setPositiveButton(R.string.save) { _, _ ->
                val raw = et.text.toString().trim()
                val low = raw.lowercase()
                if (!low.startsWith("tls://") && !low.startsWith("https://")) {
                    Toast.makeText(act, R.string.bad_format_upstream, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                if (!Prefs.parseCustomUpstream(raw).valid) {
                    Toast.makeText(act, R.string.bad_format_upstream, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                val nm = nameEt.text.toString()
                if (raw == oldSpec) {
                    // Address unchanged: only the name may have changed.
                    p.setCustomUpstreamName(oldSpec, nm)
                    rebuild()
                    return@setPositiveButton
                }
                // Address changed: the new spec must not duplicate another
                // history entry or an active upstream (exact or endpoint).
                val active = p.upstreamList()
                val activeKeys = active.map { ProviderCatalog.endpointKey(it, p) }.toSet()
                val rawKey = ProviderCatalog.endpointKey(raw, p)
                val hist = p.customUpstreamHistory()
                if (active.contains(raw) || activeKeys.contains(rawKey)
                    || hist.contains(raw)
                    || hist.any { it != oldSpec && ProviderCatalog.endpointKey(it, p) == rawKey }) {
                    Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                // Replace in place (order kept) and move the name along.
                val updated = hist.map { if (it == oldSpec) raw else it }
                p.setCustomUpstreamHistory(updated)
                p.setCustomUpstreamName(oldSpec, "")
                if (nm.isNotBlank()) p.setCustomUpstreamName(raw, nm)
                rebuild()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    /** Custom input dialog: name first, then address. The name is optional
     *  (blank = shows "Custom"); the address keeps the old explicit
     *  DoT/DoH rule. Saving here adds the custom to the HISTORY list only
     *  (never to the active list, never restarts the VPN); it joins the
     *  active upstreams only when ADD is tapped on its history card. */
    private fun showCustomDialog() {
        val act = activity ?: return
        val layout = LinearLayout(act)
        layout.orientation = LinearLayout.VERTICAL
        val pad = dp(16)
        layout.setPadding(pad, dp(8), pad, 0)
        val nameEt = EditText(act)
        nameEt.hint = "Name (optional)"
        nameEt.setSingleLine(true)
        val nameLp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        nameLp.bottomMargin = dp(8)
        nameEt.layoutParams = nameLp
        layout.addView(nameEt)
        val et = EditText(act)
        et.hint = "tls://dns.example.com or https://dns.example.com/dns-query"
        et.setSingleLine(true)
        et.layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        layout.addView(et)
        AlertDialog.Builder(act)
            .setTitle(R.string.custom_ellipsis)
            .setView(layout)
            .setPositiveButton(R.string.add) { _, _ ->
                val raw = et.text.toString().trim()
                // Custom only supports explicit DoT/DoH (no bare IP/hostname).
                val low = raw.lowercase()
                if (!low.startsWith("tls://") && !low.startsWith("https://")) {
                    Toast.makeText(act, R.string.bad_format_upstream, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                if (!Prefs.parseCustomUpstream(raw).valid) {
                    Toast.makeText(act, R.string.bad_format_upstream, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                // List-only: a custom saved here enters the HISTORY list,
                // never the active list. It joins the active upstreams only
                // when ADD is tapped on its history card (addUpstreamSpec).
                // So no max-5 check here (history caps at 20, not 5) and no
                // VPN restart (the active config is untouched).
                val p = prefs()
                val hist = p.customUpstreamHistory()
                val rawKey = ProviderCatalog.endpointKey(raw, p)
                if (hist.contains(raw)
                    || hist.any { ProviderCatalog.endpointKey(it, p) == rawKey }) {
                    Toast.makeText(act, R.string.already_in_list, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                rememberCustom(raw)
                val nm = nameEt.text.toString()
                if (nm.isNotBlank()) p.setCustomUpstreamName(raw, nm)
                rebuild()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun refreshStatus() {
        val act = activity ?: return
        val running = (act as MainActivity).isVpnRunning()
        // per-provider ping values (green when the VPN is up and the upstream
        // has answered real queries; em dash otherwise)
        for ((spec, tv) in pingViews) {
            val ms = if (running) DnsVpnService.upstreamPingMs[spec] else null
            if (ms != null) {
                tv.text = "$ms ms"
                tv.setTextColor(0xFF4ADE80.toInt())
            } else {
                tv.text = "—"
                tv.setTextColor(0xFF6E7794.toInt())
            }
        }
    }
}
