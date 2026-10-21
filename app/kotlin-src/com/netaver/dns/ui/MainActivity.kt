package com.netaver.dns.ui

import android.app.Activity
import android.app.ActivityManager
import android.app.AlertDialog
import android.app.Fragment
import android.app.FragmentManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.Toast

import com.netaver.dns.DnsVpnService
import com.netaver.dns.NetAverApp
import com.netaver.dns.R
import com.netaver.dns.util.Prefs

class MainActivity : Activity() {

    private lateinit var navButtons: Array<Button>
    private var currentTab = 0
    private val handler = Handler(Looper.getMainLooper())
    private var statsTick: Runnable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        navButtons = arrayOf(
            findViewById(R.id.nav_home), findViewById(R.id.nav_dns),
            findViewById(R.id.nav_apps), findViewById(R.id.nav_lists),
            findViewById(R.id.nav_settings)
        )
        for (i in navButtons.indices) {
            val idx = i
            navButtons[i].setOnClickListener { switchTab(idx) }
        }
        switchTab(0)
    }

    private fun switchTab(idx: Int) {
        currentTab = idx
        for (i in navButtons.indices) {
            navButtons[i].setTextColor(if (i == idx) 0xFF60A5FA.toInt() else 0xFF8B93A7.toInt())
        }
        val f: Fragment = when (idx) {
            1 -> DnsLogFragment()
            2 -> AppsFragment()
            3 -> ListsFragment()
            4 -> SettingsFragment()
            else -> HomeFragment()
        }
        // clear any detail pages from the back stack when switching tabs
        fragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
        fragmentManager.beginTransaction()
            .replace(R.id.fragment_container, f)
            .commit()
    }

    /** Open full-page detail for one app (from AppsFragment). Back returns to the list. */
    fun openAppDetail(appName: String) {
        fragmentManager.beginTransaction()
            .replace(R.id.fragment_container, AppDetailFragment.newInstance(appName))
            .addToBackStack("app_detail")
            .commit()
    }

    /** Open split-tunnel picker (from Settings). Back returns. */
    fun openSplitTunnel() {
        fragmentManager.beginTransaction()
            .replace(R.id.fragment_container, SplitTunnelFragment())
            .addToBackStack("split_tunnel")
            .commit()
    }

    /** Restart the VPN so split-tunnel changes take effect. No-op when VPN is off. */
    fun restartVpn() {
        if (!isVpnRunning()) return
        val stop = Intent(this, DnsVpnService::class.java)
        stop.action = DnsVpnService.ACTION_STOP
        startService(stop)
        handler.postDelayed({ startVpnService() }, 1200)
    }

    override fun onBackPressed() {
        if (fragmentManager.backStackEntryCount > 0) {
            fragmentManager.popBackStack()
        } else {
            super.onBackPressed()
        }
    }

    /** Called by HomeFragment power button. */
    fun toggleVpn() {
        if (isVpnRunning()) {
            val i = Intent(this, DnsVpnService::class.java)
            i.action = DnsVpnService.ACTION_STOP
            startService(i)
        } else {
            val f = fragmentManager.findFragmentById(R.id.fragment_container)
            if (f is HomeFragment) {
                startWithInternetCheck(f)
            } else {
                startVpnFlow()
            }
        }
    }

    /** Start flow with an internet check (animated on the power button). */
    private fun startWithInternetCheck(home: HomeFragment) {
        home.setChecking(true)
        Thread({
            val result = checkInternet() // 0=ok, 1=no network, 2=upstream unreachable
            runOnUiThread {
                home.setChecking(false)
                if (result == 0) {
                    startVpnFlow()
                } else {
                    showNoInternetDialog(result)
                }
            }
        }, "net-check").start()
    }

    /** The original start logic (VPN permission + service start). */
    private fun startVpnFlow() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN)
        } else {
            startVpnService()
        }
    }

    /** 0=ok, 1=no active/validated network, 2=upstream unreachable. */
    private fun checkInternet(): Int {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return 1
        val n = cm.activeNetwork ?: return 1
        val caps = cm.getNetworkCapabilities(n)
        if (caps == null
            || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        ) {
            return 1
        }
        return if (probeUpstream()) 0 else 2
    }

    /** Quick TCP probe to the first configured upstream (1.5s timeout). */
    private fun probeUpstream(): Boolean {
        return try {
            val p: Prefs = app().prefs()
            p.migrateUpstreamsIfNeeded()
            val spec = p.upstreamList().firstOrNull() ?: return true
            val host: String
            val port: Int
            if (spec.startsWith("preset:")) {
                val w = spec.removePrefix("preset:").toIntOrNull() ?: 0
                host = Prefs.upstreamIp(w)
                port = if (p.getProtocol() == 2) 443 else 853
            } else {
                val cs: Prefs.CustomSpec = Prefs.parseCustomUpstream(spec)
                if (!cs.valid) return true // invalid: service falls back; don't block start
                host = cs.host
                port = if (cs.port > 0) cs.port else if (p.getProtocol() == 2) 443 else 853
            }
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress(host, port), 1500)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun showNoInternetDialog(reason: Int) {
        val msg = if (reason == 1)
            "Tidak ada koneksi internet yang aktif."
        else
            "Server DNS tidak dapat dijangkau dari jaringan ini."
        AlertDialog.Builder(this)
            .setTitle("Tidak ada koneksi internet")
            .setMessage(msg + "\n\nTetap jalankan NetAver DNS?")
            .setPositiveButton("Tetap jalankan") { _, _ -> startVpnFlow() }
            .setNegativeButton("Batal", null)
            .show()
    }

    fun isVpnRunning(): Boolean {
        // Heuristic: our service sets a flag via app singleton is not available;
        // use ActivityManager to check.
        val am = getSystemService(ACTIVITY_SERVICE) as? ActivityManager ?: return false
        for (s in am.getRunningServices(100)) {
            if (DnsVpnService::class.java.name == s.service.className) return true
        }
        return false
    }

    private fun startVpnService() {
        val i = Intent(this, DnsVpnService::class.java)
        i.action = DnsVpnService.ACTION_START
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(i)
        } else {
            startService(i)
        }
        Toast.makeText(this, "Starting NetAver DNS…", Toast.LENGTH_SHORT).show()
        handler.postDelayed({
            val f = fragmentManager.findFragmentById(R.id.fragment_container)
            if (f is HomeFragment) f.refresh()
        }, 1500)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else if (requestCode == REQ_VPN) {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_LONG).show()
        }
    }

    override fun onResume() {
        super.onResume()
        val f = fragmentManager.findFragmentById(R.id.fragment_container)
        if (f is HomeFragment) f.refresh()
    }

    fun app(): NetAverApp = application as NetAverApp

    companion object {
        private const val REQ_VPN = 1001
    }
}
